// Shim to re-export mongo backend implementation if available at `src/database/mongo.rs`.
// Provide a minimal placeholder when the feature is not enabled to avoid build errors.

#[cfg(feature = "mongodb")]
pub use crate::database::mongo::*;

#[cfg(not(feature = "mongodb"))]
pub struct MongoConnection;

#[cfg(not(feature = "mongodb"))]
impl MongoConnection {
    pub async fn new(_conn: &str, _db: &str) -> Result<Self, ()> {
        Err(())
    }
}
