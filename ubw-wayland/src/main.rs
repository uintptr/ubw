use anyhow::Result;
use futures_util::stream::StreamExt;
use zbus::{Connection, proxy};

#[proxy(
    interface = "org.freedesktop.ScreenSaver",
    default_service = "org.freedesktop.ScreenSaver",
    default_path = "/org/freedesktop/ScreenSaver"
)]
trait ScreenSaver {
    #[zbus(signal)]
    fn active_changed(&self, active: bool) -> zbus::Result<()>;
}

#[tokio::main]
async fn main() -> Result<()> {
    let connection = Connection::session().await?;

    let proxy = ScreenSaverProxy::new(&connection).await?;

    let mut stream = proxy.receive_active_changed().await?;

    while let Some(signal) = stream.next().await {
        let args = signal.args()?;
        if args.active {
            println!("OFF");
        }
    }

    Ok(())
}
