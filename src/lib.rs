#![forbid(unsafe_code)]

pub mod audit;
pub mod fim;
pub mod mcp;
pub mod report;
pub mod schema;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
