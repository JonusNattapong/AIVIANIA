//! Database backends module.
//!
//! This module contains implementations for different database backends.

#[cfg(feature = "mongodb")]
pub mod mongo;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "mongodb")]
pub use mongo::*;
#[cfg(feature = "mysql")]
pub use mysql::*;
#[cfg(feature = "postgres")]
pub use postgres::*;
#[cfg(feature = "sqlite")]
pub use sqlite::*;
