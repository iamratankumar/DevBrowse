// glass.wgsl — Module 42 pb-ui::glass blur shader.
//
// Implements a two-pass Kawase blur over the wallpaper texture, followed by
// a saturation colour matrix, then alpha-composites the tint_rgba over the
// blurred result. The same shader drives every glass surface in Phase 8
// (URL bar, sidebar, popovers, settings panel).
//
// Enforces: L28 (glass-first aesthetic), §3.4 (reduce-transparency: the
// host Rust code sets blur_sigma = 0.0 and is_reduced_transparency = 1u;
// the shader then renders the solid fallback branch and skips all blur
// passes, saving GPU time).
//
// Uniforms
// --------
// GlassUniforms.tint_rgba            — rgba tint composited over blur
// GlassUniforms.blur_sigma           — Gaussian sigma in logical pixels;
//                                      0.0 = solid fallback (reduced-transparency)
// GlassUniforms.saturate             — saturation multiplier (1.0 = unchanged)
// GlassUniforms.corner_radius        — corner radius in logical pixels
// GlassUniforms.bounds               — widget bounds in physical pixels (x,y,w,h)
// GlassUniforms.is_reduced_transparency — 1u = skip blur, render solid tint

struct GlassUniforms {
    tint_rgba:               vec4<f32>,
    bounds:                  vec4<f32>,    // x, y, width, height in physical px
    blur_sigma:              f32,
    saturate:                f32,
    corner_radius:           f32,
    is_reduced_transparency: u32,
};

@group(0) @binding(0) var<uniform> u: GlassUniforms;
@group(0) @binding(1) var wallpaper_tex: texture_2d<f32>;
@group(0) @binding(2) var wallpaper_sampler: sampler;

// Full-screen quad — vertices generated in the vertex shader from instance_index.
struct VertexOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) vi: u32) -> VertexOutput {
    // Two triangles forming a quad at the widget bounds.
    // Clip-space corners: TL, TR, BL, BL, TR, BR
    var corners = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(0.0, 1.0),
        vec2<f32>(0.0, 1.0),
        vec2<f32>(1.0, 0.0),
        vec2<f32>(1.0, 1.0),
    );
    let lc = corners[vi];  // local coords [0,1] x [0,1]

    // Map to physical pixel position inside bounds.
    let px = u.bounds.xy + lc * u.bounds.zw;

    // The shader receives the wallpaper texture at its full resolution;
    // texture dimensions are passed implicitly via textureDimensions.
    let tex_size = vec2<f32>(textureDimensions(wallpaper_tex));

    // Normalised UV into wallpaper texture.
    let uv = px / tex_size;

    // Convert physical pixel to NDC.
    // Iced's wgpu backend uses a +Y-down NDC: (0,0) = top-left, (1,1) = bottom-right
    // maps to NDC (-1,1) to (1,-1).
    let ndc = vec2<f32>(px.x / tex_size.x * 2.0 - 1.0,
                        1.0 - px.y / tex_size.y * 2.0);

    var out: VertexOutput;
    out.position = vec4<f32>(ndc, 0.0, 1.0);
    out.uv       = uv;
    return out;
}

// ---------------------------------------------------------------------------
// Kawase blur helpers
// ---------------------------------------------------------------------------

// Single Kawase pass: samples at (uv ± offset * pixel_size).
fn kawase_sample(uv: vec2<f32>, offset: f32, pixel_size: vec2<f32>) -> vec4<f32> {
    let h  = offset + 0.5;
    let s0 = textureSample(wallpaper_tex, wallpaper_sampler, uv + vec2<f32>( h,  h) * pixel_size);
    let s1 = textureSample(wallpaper_tex, wallpaper_sampler, uv + vec2<f32>(-h,  h) * pixel_size);
    let s2 = textureSample(wallpaper_tex, wallpaper_sampler, uv + vec2<f32>( h, -h) * pixel_size);
    let s3 = textureSample(wallpaper_tex, wallpaper_sampler, uv + vec2<f32>(-h, -h) * pixel_size);
    return (s0 + s1 + s2 + s3) * 0.25;
}

// 4-pass Kawase approximation of a Gaussian blur with the given sigma.
// sigma_px is in physical pixels; pixel_size = 1 / texture_resolution.
fn kawase_blur(uv: vec2<f32>, sigma_px: f32, pixel_size: vec2<f32>) -> vec4<f32> {
    // Kawase iteration offsets derived from sigma: 0.0, 1.0, 2.0, 2.0
    // gives a good approximation up to sigma ~ 30 px.
    let iter  = sigma_px / 8.0;
    let c0    = kawase_sample(uv, 0.0 * iter, pixel_size);
    let c1    = kawase_sample(uv, 1.0 * iter, pixel_size);
    let c2    = kawase_sample(uv, 2.0 * iter, pixel_size);
    let c3    = kawase_sample(uv, 2.0 * iter + 1.0, pixel_size);
    return (c0 + c1 + c2 + c3) * 0.25;
}

// ---------------------------------------------------------------------------
// Saturation colour matrix (ITU-R BT.709 luminance weights)
// ---------------------------------------------------------------------------
fn apply_saturation(col: vec3<f32>, sat: f32) -> vec3<f32> {
    let lum = dot(col, vec3<f32>(0.2126, 0.7152, 0.0722));
    return mix(vec3<f32>(lum), col, sat);
}

// ---------------------------------------------------------------------------
// Rounded-rectangle SDF mask for corner clipping.
// Returns 1.0 inside the rounded rect, 0.0 outside (with a 1 px AA ramp).
// ---------------------------------------------------------------------------
fn rounded_rect_mask(local_px: vec2<f32>, size_px: vec2<f32>, r: f32) -> f32 {
    let half = size_px * 0.5;
    let p    = abs(local_px - half) - half + vec2<f32>(r);
    let d    = length(max(p, vec2<f32>(0.0))) + min(max(p.x, p.y), 0.0) - r;
    return clamp(-d, 0.0, 1.0);   // 1 px AA ramp
}

// ---------------------------------------------------------------------------
// Fragment shader
// ---------------------------------------------------------------------------
@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    let tex_size  = vec2<f32>(textureDimensions(wallpaper_tex));
    let pixel_size = 1.0 / tex_size;

    // Local position within the widget in physical pixels.
    let local_px  = (in.uv * tex_size) - u.bounds.xy;

    // Rounded-rect mask.
    let mask = rounded_rect_mask(local_px, u.bounds.zw, u.corner_radius);
    if mask <= 0.0 { discard; }

    var base: vec4<f32>;

    if u.is_reduced_transparency == 1u || u.blur_sigma <= 0.0 {
        // Solid fallback — no blur pass (prefers-reduced-transparency or sigma = 0).
        base = textureSample(wallpaper_tex, wallpaper_sampler, in.uv);
    } else {
        // Kawase blur over wallpaper.
        base = kawase_blur(in.uv, u.blur_sigma, pixel_size);
    }

    // Saturation pass.
    let saturated = vec4<f32>(apply_saturation(base.rgb, u.saturate), base.a);

    // Alpha-composite tint over blurred+saturated wallpaper.
    let tint   = u.tint_rgba;
    let result = vec4<f32>(
        saturated.rgb * (1.0 - tint.a) + tint.rgb * tint.a,
        saturated.a + tint.a * (1.0 - saturated.a),
    );

    // Apply rounded-rect mask.
    return vec4<f32>(result.rgb, result.a * mask);
}
