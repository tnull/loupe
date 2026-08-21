//! Credential-free loopback adapter used inside an agent sandbox.
//!
//! The adapter accepts one local TCP connection and relays it to the
//! per-job model broker Unix socket. It has no provider destination or
//! credential of its own.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UnixStream};

#[derive(Debug)]
pub struct ModelProxy {
	listener: TcpListener,
	socket_path: PathBuf,
}

impl ModelProxy {
	pub async fn bind(socket_path: PathBuf, listen: SocketAddr, port_file: &Path) -> Result<Self> {
		if !listen.ip().is_loopback() {
			anyhow::bail!("model proxy listener must use a loopback address");
		}
		let listener = TcpListener::bind(listen)
			.await
			.with_context(|| format!("binding model proxy at {listen}"))?;
		let local_addr = listener.local_addr().context("reading model proxy listener address")?;
		tokio::fs::write(port_file, format!("{}\n", local_addr.port()))
			.await
			.with_context(|| format!("writing model proxy port file at {}", port_file.display()))?;
		Ok(Self { listener, socket_path })
	}

	pub fn local_addr(&self) -> SocketAddr {
		self.listener.local_addr().expect("bound model proxy listener has an address")
	}

	pub fn base_url(&self) -> String {
		format!("http://{}", self.local_addr())
	}

	pub async fn relay_one(self) -> Result<()> {
		let (mut tcp, peer) =
			self.listener.accept().await.context("accepting model API connection")?;
		if !peer.ip().is_loopback() {
			anyhow::bail!("model proxy refused a non-loopback peer");
		}
		let mut unix = UnixStream::connect(&self.socket_path).await.with_context(|| {
			format!("connecting model broker socket at {}", self.socket_path.display())
		})?;
		tokio::io::copy_bidirectional(&mut tcp, &mut unix)
			.await
			.context("relaying model API connection")?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpStream, UnixListener};

	use super::*;

	#[tokio::test]
	async fn relays_one_loopback_connection_to_the_job_socket() {
		let scratch = tempfile::tempdir().unwrap();
		let socket = scratch.path().join("broker.sock");
		let unix = UnixListener::bind(&socket).unwrap();
		let echo = tokio::spawn(async move {
			let (mut stream, _) = unix.accept().await.unwrap();
			let mut request = [0; 4];
			stream.read_exact(&mut request).await.unwrap();
			assert_eq!(&request, b"ping");
			stream.write_all(b"pong").await.unwrap();
		});

		let port_file = scratch.path().join("model.port");
		let proxy = ModelProxy::bind(
			socket,
			SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
			&port_file,
		)
		.await
		.unwrap();
		let address = proxy.local_addr();
		assert_eq!(std::fs::read_to_string(&port_file).unwrap(), format!("{}\n", address.port()));
		let relay = tokio::spawn(proxy.relay_one());

		let mut client = TcpStream::connect(address).await.unwrap();
		client.write_all(b"ping").await.unwrap();
		let mut response = [0; 4];
		client.read_exact(&mut response).await.unwrap();
		assert_eq!(&response, b"pong");
		client.shutdown().await.unwrap();

		relay.await.unwrap().unwrap();
		echo.await.unwrap();
	}

	#[tokio::test]
	async fn refuses_a_non_loopback_listener() {
		let scratch = tempfile::tempdir().unwrap();
		let error = ModelProxy::bind(
			scratch.path().join("unused.sock"),
			"0.0.0.0:0".parse().unwrap(),
			&scratch.path().join("model.port"),
		)
		.await
		.expect_err("the credential-free adapter must remain sandbox-local");
		assert!(error.to_string().contains("loopback"), "unexpected error: {error:#}");
	}
}
