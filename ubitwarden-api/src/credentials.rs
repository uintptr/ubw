use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct BwCredentials {
    pub email: String,
    pub password: String,
    pub server_url: String,
}
