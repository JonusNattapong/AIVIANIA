// Shim to re-export mysql backend implementation if available at `src/database/mysql.rs`.
// If the full implementation is not present, provide a minimal placeholder to avoid
// compile-time mod resolution errors when the feature flag is toggled.

#[cfg(feature = "mysql")]
pub use crate::database::mysql::*;

#[cfg(not(feature = "mysql"))]
pub struct MysqlConnection;

#[cfg(not(feature = "mysql"))]
impl MysqlConnection {
    pub async fn new(_conn: &str) -> Result<Self, ()> {
        Err(())
    }
}
