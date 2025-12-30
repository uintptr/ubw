use anyhow::{Result, bail};

use crate::commands::xss::XSecureLockArgs;

pub async fn command_xsecurelock(_args: XSecureLockArgs) -> Result<()> {
    bail!("not supported")
}
