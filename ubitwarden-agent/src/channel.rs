use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ubitwarden::error::Result;

pub trait AgentChannelTrait: Serialize {
    async fn write<W>(&self, stream: &mut W) -> Result<()>
    where
        W: AsyncWriteExt + Unpin,
    {
        let data = serde_json::to_string(self)?;

        let len: u32 = data.as_bytes().len().try_into()?;

        stream.write_u32(len).await?;
        stream.write_all(data.as_bytes()).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn read<D, R>(stream: &mut R) -> Result<D>
    where
        D: DeserializeOwned,
        R: AsyncReadExt + Unpin,
    {
        let len: usize = stream.read_u32().await?.try_into()?;

        let mut buf = vec![0u8; len];

        stream.read_exact(&mut buf).await?;

        let req: D = serde_json::from_slice(&buf)?;

        Ok(req)
    }
}
