// Module 4 — pb-ipc transport layer.
//
// Framing: 4-byte big-endian u32 length prefix followed by payload bytes.
//
// Platform backends (same public API on every supported target):
//   Unix    — tokio::net::UnixStream / UnixListener (AF_UNIX domain sockets)
//
// Windows backend is deferred to Phase 11.9 (Module 93). The previous v1.4
// named-pipe implementation — which serialized reads and writes through a
// shared Mutex on a single pipe handle — was removed in v1.9 along with
// every other Windows code path. The Phase 11.9 replacement is a two-pipe
// duplex (one pipe per direction) so concurrent reads and writes never
// contend on the same handle, plus an explicit per-pipe security
// descriptor restricting the ACL to the current user SID. See
// docs/architecture.md §6 Phase 11.9 Module 93 for the full requirements.
//
// Adding a new platform: implement IpcListener, IpcConnection, IpcReadHalf,
// IpcWriteHalf in a new cfg-gated module and re-export below.
//
// SECURITY INVARIANT: MAX_MESSAGE_BYTES is enforced on both send and recv.
// Enforcing on recv prevents a compromised peer from triggering a heap-bomb
// before the protobuf layer has a chance to validate anything.

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum serialized message size: 4 MiB.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("message size {0} exceeds MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES})")]
    MessageTooLarge(usize),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

// ── Shared framing (platform-independent) ────────────────────────────────────

async fn write_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), IpcError> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge(payload.len()));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(IpcError::ConnectionClosed);
        }
        Err(e) => return Err(IpcError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(IpcError::MessageTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

// ── Test-only duplex backend (cfg-gated) ─────────────────────────────────────
//
// Behind the `testkit` feature, pb-testkit exposes an in-memory IPC pair
// backed by `tokio::io::duplex`. Tests built on the pair never touch the
// filesystem, never bind a socket, and run in parallel without unique-path
// dance. Production code paths never see this type — the feature is OFF by
// default and pb-testkit owns the only consumer.
//
// SECURITY INVARIANT — never weaken:
//   The duplex path reuses the same `read_frame` / `write_frame` helpers as
//   the Unix backend so framing is exercised identically. A test that passes
//   under DuplexConnection covers the production framing surface; do not
//   introduce a parallel framing implementation here.

#[cfg(feature = "testkit")]
pub mod testkit {
    //! In-memory IPC fixture surface. Gated on `feature = "testkit"`.
    //!
    //! Use [`DuplexConnection::pair`] to obtain `(a, b)` where bytes written
    //! to one end are readable from the other, with the same length-prefixed
    //! framing the production transport uses.

    use super::{read_frame, write_frame, IpcError, MAX_MESSAGE_BYTES};
    use tokio::io::DuplexStream;

    /// Default per-end buffer for the duplex stream. Sized so a single
    /// `MAX_MESSAGE_BYTES` payload plus its length prefix fits without
    /// blocking; tests that need streaming back-pressure call
    /// [`DuplexConnection::pair_with_capacity`] explicitly.
    pub const DEFAULT_DUPLEX_CAPACITY: usize = MAX_MESSAGE_BYTES + 4;

    /// Duplex-backed end of a pb-ipc connection. API mirrors the
    /// production [`super::IpcConnection`] (`send`, `recv`, `split`).
    pub struct DuplexConnection {
        inner: DuplexStream,
    }

    impl DuplexConnection {
        /// Create a connected pair with the default per-end capacity.
        pub fn pair() -> (Self, Self) {
            Self::pair_with_capacity(DEFAULT_DUPLEX_CAPACITY)
        }

        /// Create a connected pair with an explicit per-end capacity.
        ///
        /// `capacity` smaller than a target frame's `len + 4` causes
        /// `send` to apply back-pressure; useful for partial-write tests.
        pub fn pair_with_capacity(capacity: usize) -> (Self, Self) {
            let (a, b) = tokio::io::duplex(capacity);
            (Self { inner: a }, Self { inner: b })
        }

        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            write_frame(&mut self.inner, payload).await
        }

        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            read_frame(&mut self.inner).await
        }

        /// Split into owned read/write halves backed by the same duplex.
        pub fn split(self) -> (DuplexReadHalf, DuplexWriteHalf) {
            let (r, w) = tokio::io::split(self.inner);
            (DuplexReadHalf { inner: r }, DuplexWriteHalf { inner: w })
        }
    }

    pub struct DuplexReadHalf {
        inner: tokio::io::ReadHalf<DuplexStream>,
    }

    impl DuplexReadHalf {
        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            read_frame(&mut self.inner).await
        }
    }

    pub struct DuplexWriteHalf {
        inner: tokio::io::WriteHalf<DuplexStream>,
    }

    impl DuplexWriteHalf {
        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            write_frame(&mut self.inner, payload).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn round_trip_small_message() {
            let (mut a, mut b) = DuplexConnection::pair();
            a.send(b"ping").await.unwrap();
            assert_eq!(b.recv().await.unwrap(), b"ping");
        }

        #[tokio::test]
        async fn split_halves_round_trip() {
            let (a, b) = DuplexConnection::pair();
            let (mut ar, _aw) = a.split();
            let (_br, mut bw) = b.split();
            bw.send(b"split").await.unwrap();
            assert_eq!(ar.recv().await.unwrap(), b"split");
        }

        #[tokio::test]
        async fn rejects_oversized_send() {
            let (mut a, _b) = DuplexConnection::pair();
            let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
            let err = a.send(&big).await.unwrap_err();
            assert!(matches!(err, IpcError::MessageTooLarge(_)));
        }

        #[tokio::test]
        async fn closed_peer_surfaces_connection_closed() {
            let (a, mut b) = DuplexConnection::pair();
            drop(a);
            let err = b.recv().await.unwrap_err();
            assert!(matches!(err, IpcError::ConnectionClosed));
        }
    }
}

// ── Unix backend (AF_UNIX domain sockets) ────────────────────────────────────

#[cfg(unix)]
pub use unix_impl::{IpcConnection, IpcListener, IpcReadHalf, IpcWriteHalf};

#[cfg(unix)]
mod unix_impl {
    use super::{read_frame, write_frame, IpcError};
    use std::path::Path;
    use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::{UnixListener, UnixStream};

    pub struct IpcListener {
        inner: UnixListener,
    }

    impl IpcListener {
        pub fn bind(path: &Path) -> Result<Self, IpcError> {
            Ok(Self {
                inner: UnixListener::bind(path)?,
            })
        }

        pub async fn accept(&self) -> Result<IpcConnection, IpcError> {
            let (stream, _) = self.inner.accept().await?;
            Ok(IpcConnection { inner: stream })
        }
    }

    pub struct IpcConnection {
        inner: UnixStream,
    }

    impl IpcConnection {
        pub async fn connect(path: &Path) -> Result<Self, IpcError> {
            Ok(Self {
                inner: UnixStream::connect(path).await?,
            })
        }

        /// Split into owned halves for concurrent reader/writer task use.
        pub fn split(self) -> (IpcReadHalf, IpcWriteHalf) {
            let (r, w) = self.inner.into_split();
            (IpcReadHalf { inner: r }, IpcWriteHalf { inner: w })
        }

        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            write_frame(&mut self.inner, payload).await
        }

        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            read_frame(&mut self.inner).await
        }
    }

    pub struct IpcReadHalf {
        inner: OwnedReadHalf,
    }

    impl IpcReadHalf {
        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            read_frame(&mut self.inner).await
        }
    }

    pub struct IpcWriteHalf {
        inner: OwnedWriteHalf,
    }

    impl IpcWriteHalf {
        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            write_frame(&mut self.inner, payload).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::tempdir;

        #[tokio::test]
        async fn round_trip_small_message() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("ipc.sock");
            let listener = IpcListener::bind(&path).unwrap();
            let path2 = path.clone();
            let client = tokio::spawn(async move {
                let mut conn = IpcConnection::connect(&path2).await.unwrap();
                conn.send(b"ping").await.unwrap();
                conn.recv().await.unwrap()
            });
            let mut server = listener.accept().await.unwrap();
            let msg = server.recv().await.unwrap();
            assert_eq!(msg, b"ping");
            server.send(b"pong").await.unwrap();
            let reply = client.await.unwrap();
            assert_eq!(reply, b"pong");
        }

        #[tokio::test]
        async fn round_trip_split_halves() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("ipc_split.sock");
            let listener = IpcListener::bind(&path).unwrap();
            let path2 = path.clone();
            let client = tokio::spawn(async move {
                let conn = IpcConnection::connect(&path2).await.unwrap();
                let (mut r, mut w) = conn.split();
                w.send(b"split-ping").await.unwrap();
                r.recv().await.unwrap()
            });
            let mut server = listener.accept().await.unwrap();
            let msg = server.recv().await.unwrap();
            assert_eq!(msg, b"split-ping");
            server.send(b"split-pong").await.unwrap();
            let reply = client.await.unwrap();
            assert_eq!(reply, b"split-pong");
        }

        #[tokio::test]
        async fn rejects_oversized_send() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("ipc_big.sock");
            let listener = IpcListener::bind(&path).unwrap();
            let path2 = path.clone();
            tokio::spawn(async move { listener.accept().await.ok() });
            let mut conn = IpcConnection::connect(&path2).await.unwrap();
            let big = vec![0u8; super::super::MAX_MESSAGE_BYTES + 1];
            let err = conn.send(&big).await.unwrap_err();
            assert!(matches!(err, IpcError::MessageTooLarge(_)));
        }

        #[tokio::test]
        async fn detects_connection_closed() {
            let dir = tempdir().unwrap();
            let path = dir.path().join("ipc_close.sock");
            let listener = IpcListener::bind(&path).unwrap();
            let path2 = path.clone();
            let client = tokio::spawn(async move {
                let conn = IpcConnection::connect(&path2).await.unwrap();
                drop(conn);
            });
            let mut server = listener.accept().await.unwrap();
            client.await.unwrap();
            let err = server.recv().await.unwrap_err();
            assert!(matches!(err, IpcError::ConnectionClosed));
        }
    }
}

// ── Windows backend ───────────────────────────────────────────────────────────
//
// Deferred to Phase 11.9 — Module 93 (two-pipe duplex named-pipe transport
// with per-pipe SID-restricted security descriptors). The placeholder
// `compile_error!` below makes accidental Windows builds fail loudly until
// that module lands. Do not reintroduce the v1.4 single-pipe Mutex backend.

#[cfg(windows)]
compile_error!(
    "Windows IPC backend deferred to Phase 11.9 (Module 93). \
     See docs/architecture.md §6 Phase 11.9. \
     CI builds Linux/macOS only until this phase ships."
);

// ── Unsupported platforms ─────────────────────────────────────────────────────

#[cfg(not(any(unix, windows)))]
compile_error!(
    "pb-ipc transport requires a Unix (AF_UNIX sockets) target. \
     Windows support is deferred to Phase 11.9. \
     Implement a platform backend in transport.rs before building any other target."
);
