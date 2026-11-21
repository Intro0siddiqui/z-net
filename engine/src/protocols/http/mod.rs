pub mod client;
pub mod cookie_jar;
pub mod h1;
pub mod h2;
pub mod pool;

pub enum HttpVersion {
    Http11,
    Http2,
}
