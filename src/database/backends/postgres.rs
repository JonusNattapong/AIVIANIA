// Shim to re-export the postgres backend implementation located at `src/database/postgres.rs`.
// This keeps the `database::backends` module layout consistent while the implementation
// lives at `src/database/postgres.rs`.

pub use crate::database::postgres::*;
