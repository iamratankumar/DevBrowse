// Module 5 — protobuf code generation via protox (pure Rust, no protoc needed).
// protox parses the .proto file and produces a FileDescriptorSet;
// prost-build turns that into Rust types.

fn main() {
    let fds = protox::compile(["proto/messages.proto"], ["proto/"])
        .expect("protox failed — check proto/messages.proto for syntax errors");

    prost_build::Config::new()
        .compile_fds(fds)
        .expect("prost_build failed");
}
