use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct BwCredentials {
    pub email: String,
    pub password: String,
    pub server_url: String,
}
