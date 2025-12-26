use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use crate::error::Result;

async fn store_data<K, V>(key: K, value: V) -> Result<()>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let command = format!("write:{}:{}", key.as_ref(), value.as_ref());

    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;

    write_string(&mut stream, command).await
}

async fn fetch_data(key: &str) -> Result<String> {
    let command = format!("read:{key}");

    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;

    write_string(&mut stream, command).await?;
    read_string(&mut stream).await
}

////////////////////////////////////////////////////////////////////////////////
// PROTECTED
////////////////////////////////////////////////////////////////////////////////

pub(crate) fn create_socket_name() -> String {
    let username = whoami::username();
    format!("\0ubw_{username}")
}

pub(crate) async fn read_string(stream: &mut UnixStream) -> Result<String> {
    let len = stream.read_i32().await?;
    let len: usize = len.try_into()?;

    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf).await?;

    let s = String::from_utf8(buf)?;

    Ok(s)
}

pub(crate) async fn write_string<S>(stream: &mut UnixStream, input: S) -> Result<()>
where
    S: AsRef<str>,
{
    let len = input.as_ref().len();
    let len: i32 = len.try_into()?;

    stream.write_i32(len).await?;

    stream.write_all(input.as_ref().as_bytes()).await?;

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC
////////////////////////////////////////////////////////////////////////////////

pub async fn ping_server() -> Result<()> {
    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;
    write_string(&mut stream, "ping").await
}

pub async fn stop_server() -> Result<()> {
    let socket_name = create_socket_name();
    let mut stream = UnixStream::connect(socket_name).await?;
    write_string(&mut stream, "stop").await
}

pub async fn store_user_data<D, K>(key: K, data: D) -> Result<()>
where
    D: AsRef<str>,
    K: AsRef<str>,
{
    store_data(key, data).await
}

pub async fn fetch_user_data<K>(key: K) -> Result<String>
where
    K: AsRef<str>,
{
    fetch_data(key.as_ref()).await
}
