pub mod doh3;
pub mod dot;

pub struct PrivacyDns {
    pub doh3: doh3::Doh3Client,
    pub dot: dot::DotClient,
}

impl PrivacyDns {
    pub fn new() -> Self {
        Self {
            doh3: doh3::Doh3Client::new(),
            dot: dot::DotClient::new(),
        }
    }
}
