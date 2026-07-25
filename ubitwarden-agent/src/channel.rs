use std::io::{Read, Write};

use serde::{Serialize, de::DeserializeOwned};
use ubitwarden::error::Result;

pub trait AgentChannelTrait: Serialize {
    fn write<W>(&self, stream: &mut W) -> Result<()>
    where
        W: Write,
    {
        let data = serde_json::to_string(self)?;

        let len: u32 = data.len().try_into()?;

        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(data.as_bytes())?;
        stream.flush()?;

        Ok(())
    }

    fn read<D, R>(stream: &mut R) -> Result<D>
    where
        D: DeserializeOwned,
        R: Read,
    {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;

        let len: usize = u32::from_be_bytes(len_buf).try_into()?;

        let mut buf = vec![0u8; len];

        stream.read_exact(&mut buf)?;

        let req: D = serde_json::from_slice(&buf)?;

        Ok(req)
    }
}
