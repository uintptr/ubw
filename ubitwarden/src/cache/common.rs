use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub(crate) const BW_UNIX_SOCKET_NAME: &str = "\0ubw";

async fn store_data<K, V>(key: K, value: V) -> Result<()>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    let command = format!("write:{}:{}", key.as_ref(), value.as_ref());

    let mut stream = UnixStream::connect(BW_UNIX_SOCKET_NAME).await?;

    write_string(&mut stream, command).await
}

async fn fetch_data(key: &str) -> Result<String> {
    let command = format!("read:{key}");

    let mut stream = UnixStream::connect(BW_UNIX_SOCKET_NAME).await?;

    write_string(&mut stream, command).await?;
    read_string(&mut stream).await
}

////////////////////////////////////////////////////////////////////////////////
// PROTECTED
////////////////////////////////////////////////////////////////////////////////

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

pub async fn ping() -> Result<()> {
    let mut stream = UnixStream::connect(BW_UNIX_SOCKET_NAME).await?;
    write_string(&mut stream, "ping").await
}

pub async fn store_user_data<D, E, K>(email: E, key: K, data: D) -> Result<()>
where
    D: AsRef<str>,
    E: AsRef<str>,
    K: AsRef<str>,
{
    let key = format!("{}_{}", email.as_ref(), key.as_ref());
    store_data(key, data).await
}

pub async fn fetch_user_data<E, K>(email: E, key: K) -> Result<String>
where
    E: AsRef<str>,
    K: AsRef<str>,
{
    let key = format!("{}_{}", email.as_ref(), key.as_ref());
    fetch_data(&key).await
}
