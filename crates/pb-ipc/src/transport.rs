// Module 4 — pb-ipc transport layer.
//
// Framing: 4-byte big-endian u32 length prefix followed by payload bytes.
//
// Platform backends (same public API on every target):
//   Unix    — tokio::net::UnixStream / UnixListener (AF_UNIX domain sockets)
//   Windows — tokio::net::windows::named_pipe (NamedPipeServer / ClientOptions)
//             Reads and writes share a Mutex; fully concurrent split() is a
//             TODO tracked in docs/architecture.md — see Windows transport note.
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

// ── Windows backend (named pipes) ─────────────────────────────────────────────
//
// Named pipes give the same length-prefix framing over a handle pair.
// `to_pipe_name` maps a unix-style socket path to \\.\pipe\<filename> so
// callers use the same Path API on both platforms.
//
// Concurrency note: `IpcReadHalf` and `IpcWriteHalf` share the same
// `Arc<Mutex<WinStream>>`. A concurrent recv + send will serialize through
// the lock (Windows named pipes require OVERLAPPED I/O for true concurrency
// without handle duplication). For the IPC message volumes DevBrowse expects
// this is fine; upgrade to a two-pipe duplex model (one pipe per direction)
// if benchmarks show contention.

#[cfg(windows)]
pub use windows_impl::{IpcConnection, IpcListener, IpcReadHalf, IpcWriteHalf};

#[cfg(windows)]
mod windows_impl {
    use super::{read_frame, write_frame, IpcError};
    use std::path::Path;
    use std::sync::Arc;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use tokio::sync::Mutex;

    fn to_pipe_name(path: &Path) -> String {
        let name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy();
        format!(r"\\.\pipe\devbrowse-{name}")
    }

    enum WinStream {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    pub struct IpcListener {
        pipe_name: String,
        // The pending server instance: accept() waits for a client on the
        // current instance and immediately creates the next one so no
        // connection window is missed.
        pending: Mutex<NamedPipeServer>,
    }

    impl IpcListener {
        pub fn bind(path: &Path) -> Result<Self, IpcError> {
            let pipe_name = to_pipe_name(path);
            let server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)?;
            Ok(Self {
                pipe_name,
                pending: Mutex::new(server),
            })
        }

        pub async fn accept(&self) -> Result<IpcConnection, IpcError> {
            let mut guard = self.pending.lock().await;
            guard.connect().await?;
            let next = ServerOptions::new().create(&self.pipe_name)?;
            let accepted = std::mem::replace(&mut *guard, next);
            Ok(IpcConnection {
                inner: Arc::new(Mutex::new(WinStream::Server(accepted))),
            })
        }
    }

    pub struct IpcConnection {
        inner: Arc<Mutex<WinStream>>,
    }

    impl IpcConnection {
        pub async fn connect(path: &Path) -> Result<Self, IpcError> {
            let pipe_name = to_pipe_name(path);
            let client = ClientOptions::new().open(&pipe_name)?;
            Ok(Self {
                inner: Arc::new(Mutex::new(WinStream::Client(client))),
            })
        }

        pub fn split(self) -> (IpcReadHalf, IpcWriteHalf) {
            (
                IpcReadHalf {
                    inner: self.inner.clone(),
                },
                IpcWriteHalf { inner: self.inner },
            )
        }

        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            let mut guard = self.inner.lock().await;
            match &mut *guard {
                WinStream::Server(s) => write_frame(s, payload).await,
                WinStream::Client(c) => write_frame(c, payload).await,
            }
        }

        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            let mut guard = self.inner.lock().await;
            match &mut *guard {
                WinStream::Server(s) => read_frame(s).await,
                WinStream::Client(c) => read_frame(c).await,
            }
        }
    }

    pub struct IpcReadHalf {
        inner: Arc<Mutex<WinStream>>,
    }

    impl IpcReadHalf {
        pub async fn recv(&mut self) -> Result<Vec<u8>, IpcError> {
            let mut guard = self.inner.lock().await;
            match &mut *guard {
                WinStream::Server(s) => read_frame(s).await,
                WinStream::Client(c) => read_frame(c).await,
            }
        }
    }

    pub struct IpcWriteHalf {
        inner: Arc<Mutex<WinStream>>,
    }

    impl IpcWriteHalf {
        pub async fn send(&mut self, payload: &[u8]) -> Result<(), IpcError> {
            let mut guard = self.inner.lock().await;
            match &mut *guard {
                WinStream::Server(s) => write_frame(s, payload).await,
                WinStream::Client(c) => write_frame(c, payload).await,
            }
        }
    }
}

// ── Unsupported platforms ─────────────────────────────────────────────────────

#[cfg(not(any(unix, windows)))]
compile_error!(
    "pb-ipc transport requires a Unix (AF_UNIX sockets) or Windows (named pipes) target. \
     Implement a platform backend in transport.rs before building."
);
