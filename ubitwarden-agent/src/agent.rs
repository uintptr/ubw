use log::{error, info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use ubitwarden::{api::BwApi, credentials::BwCredentials, error::Result, session::BwSession};

pub struct UBWAgent {
    stream: UnixStream,
}

impl UBWAgent {
    pub async fn new() -> Result<Self> {
        let socket_name = UBWAgent::create_socket_name();

        let stream = UnixStream::connect(socket_name).await?;

        Ok(Self { stream })
    }

    #[must_use]
    pub fn create_socket_name() -> String {
        format!("\0ubw_{}", whoami::username())
    }

    async fn write_string<S>(&mut self, input: S) -> Result<()>
    where
        S: AsRef<str>,
    {
        let len = input.as_ref().len();
        let len: i32 = len.try_into()?;

        self.stream.write_i32(len).await?;
        self.stream.write_all(input.as_ref().as_bytes()).await?;

        Ok(())
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.stream.read_i32().await?;
        let len: usize = len.try_into()?;

        let mut buf = vec![0u8; len];

        self.stream.read_exact(&mut buf).await?;

        let s = String::from_utf8(buf)?;

        Ok(s)
    }

    async fn store_data<K, V>(&mut self, key: K, value: V) -> Result<()>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let command = format!("write:{}:{}", key.as_ref(), value.as_ref());
        self.write_string(command).await
    }

    async fn store_user_data<D, K>(&mut self, key: K, data: D) -> Result<()>
    where
        D: AsRef<str>,
        K: AsRef<str>,
    {
        self.store_data(key, data).await
    }

    async fn fetch_data(&mut self, key: &str) -> Result<String> {
        let command = format!("read:{key}");

        self.write_string(command).await?;
        self.read_string().await
    }

    pub async fn fetch_user_data<K>(&mut self, key: K) -> Result<String>
    where
        K: AsRef<str>,
    {
        self.fetch_data(key.as_ref()).await
    }

    ////////////////////////////////////////////////////////////////////////////
    // PUBLIC
    ////////////////////////////////////////////////////////////////////////////

    pub async fn stop(&mut self) -> Result<()> {
        self.write_string("stop").await
    }

    //
    // Session
    //
    pub async fn delete_session(&mut self) -> Result<()> {
        self.write_string("delete:session").await
    }

    pub async fn store_session(&mut self, session: &BwSession) -> Result<()> {
        let encoded_session = session.to_string();
        self.store_user_data("session", encoded_session).await
    }

    pub async fn fetch_session(&mut self) -> Result<BwSession> {
        let data = self.fetch_user_data("session").await?;
        let session: BwSession = data.parse()?;
        Ok(session)
    }

    pub async fn load_session(&mut self) -> Result<BwSession> {
        if let Ok(session) = self.fetch_session().await {
            if session.expired()? {
                warn!("session expired");
                //
                // see if the session is still usable ( expired )
                //
            } else {
                return Ok(session);
            }
        }

        let creds = self.fetch_credentials().await?;

        //
        // Either it didn't exist or it was expired. let's rejoin
        //
        let api = BwApi::new(&creds.email, &creds.server_url)?;

        let auth = api.auth(&creds.password).await?;

        let session = BwSession::new(&creds, &auth)?;

        // best effort. not fatal since we got what we wanted
        if let Err(e) = self.store_session(&session).await {
            error!("Unable to store session: ({e})");
        }

        Ok(session)
    }

    //
    // Credentials
    //
    pub async fn delete_credentials(&mut self) -> Result<()> {
        self.write_string("delete:credentials").await
    }

    pub async fn fetch_credentials(&mut self) -> Result<BwCredentials> {
        let data = self.fetch_user_data("credentials").await?;
        let creds: BwCredentials = serde_json::from_str(&data)?;
        info!("found credentials for {}", creds.email);
        Ok(creds)
    }

    pub async fn store_credentials<E, P, U>(&mut self, email: E, server_url: U, password: P) -> Result<()>
    where
        E: Into<String>,
        U: Into<String>,
        P: Into<String>,
    {
        let creds = BwCredentials {
            email: email.into(),
            password: password.into(),
            server_url: server_url.into(),
        };

        let encoded_creds = serde_json::to_string(&creds)?;

        self.store_user_data("credentials", encoded_creds).await?;

        Ok(())
    }
}
