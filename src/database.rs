//! Database module - SQLite integration with async operations.
//!
//! This module provides database connectivity, connection pooling, and user management
//! for authentication and data persistence.

use tokio_rusqlite::Connection as AsyncConnection;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;

/// Database connection pool.
pub struct Database {
    conn: Arc<AsyncConnection>,
}

impl Database {
    /// Create a new database connection to an in-memory SQLite database.
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn = AsyncConnection::open_in_memory().await?;
        let db = Self {
            conn: Arc::new(conn),
        };
        db.init_tables().await?;
        Ok(db)
    }

    /// Create a new database connection to a file-based SQLite database.
    pub async fn new_with_path(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn = AsyncConnection::open(path).await?;
        let db = Self {
            conn: Arc::new(conn),
        };
        db.init_tables().await?;
        Ok(db)
    }

    /// Initialize database tables.
    async fn init_tables(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.conn.call(|conn| {
            // Users table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            )?;

            // Roles table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )",
                [],
            )?;

            // User roles junction table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS user_roles (
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
                )",
                [],
            )?;

            Ok(())
        }).await?;
        Ok(())
    }

    /// Create a new user.
    pub async fn create_user(&self, username: &str, password_hash: &str) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
        let username = username.to_string();
        let password_hash = password_hash.to_string();

        let user_id = self.conn.call(move |conn| {
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
                [&username, &password_hash],
            )?;
            Ok(conn.last_insert_rowid())
        }).await?;

        Ok(user_id)
    }

    /// Get user by username.
    pub async fn get_user(&self, username: &str) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        let username = username.to_string();

        let user = self.conn.call(move |conn| {
            let mut stmt = conn.prepare("SELECT id, username, password_hash, created_at FROM users WHERE username = ?1")?;
            let mut rows = stmt.query_map([&username], |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?;

            if let Some(user) = rows.next() {
                Ok(Some(user?))
            } else {
                Ok(None)
            }
        }).await?;

        Ok(user)
    }

    /// Verify user credentials.
    pub async fn verify_credentials(&self, username: &str, password: &str) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(user) = self.get_user(username).await? {
            if Database::verify_password(password, &user.password_hash)? {
                Ok(Some(user))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
}

/// User model.

    /// Hash a password using Argon2.
    pub fn hash_password(password: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash.
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let parsed_hash = PasswordHash::new(hash)?;
        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    /// Create default roles if they don't exist.
    pub async fn create_default_roles(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let roles = vec![
            ("admin", "Administrator with full access"),
            ("user", "Regular user with basic access"),
            ("moderator", "Moderator with elevated permissions"),
        ];

        for (name, description) in roles {
            self.conn.call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO roles (name, description) VALUES (?1, ?2)",
                    [name, description],
                )?;
                Ok(())
            }).await?;
        }
        Ok(())
    }

    /// Assign a role to a user.
    pub async fn assign_role_to_user(&self, user_id: i64, role_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let role_name = role_name.to_string();
        self.conn.call(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id)
                 SELECT ?1, id FROM roles WHERE name = ?2",
                (user_id, role_name),
            )?;
            Ok(())
        }).await?;
        Ok(())
    }

    /// Get roles for a user.
    pub async fn get_user_roles(&self, user_id: i64) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let roles = self.conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT r.name FROM roles r
                 INNER JOIN user_roles ur ON r.id = ur.role_id
                 WHERE ur.user_id = ?1"
            )?;
            let roles = stmt.query_map([user_id], |row| row.get(0))?
                .collect::<Result<Vec<String>, _>>()?;
            Ok(roles)
        }).await?;
        Ok(roles)
    }

    /// Check if user has a specific role.
    pub async fn user_has_role(&self, user_id: i64, role_name: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let role_name = role_name.to_string();
        let count = self.conn.call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM user_roles ur
                 INNER JOIN roles r ON ur.role_id = r.id
                 WHERE ur.user_id = ?1 AND r.name = ?2"
            )?;
            let count: i64 = stmt.query_row((user_id, role_name), |row| row.get(0))?;
            Ok(count)
        }).await?;
        Ok(count > 0)
    }

    /// Ping the database with a minimal query to check connectivity.
    pub async fn ping(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let res = self.conn.call(|conn| {
            let mut stmt = conn.prepare("SELECT 1")?;
            let mut rows = stmt.query([])?;
            if let Some(_) = rows.next()? {
                Ok(true)
            } else {
                Ok(true)
            }
        }).await?;
        Ok(res)
    }

    /// Ping and check required schema existence (users table present)
    pub async fn ping_with_schema_check(&self) -> Result<(bool, bool), Box<dyn std::error::Error + Send + Sync>> {
        let up = self.ping().await?;
        let schema_ok = if up {
            self.conn.call(|conn| {
                let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")?;
                let mut rows = stmt.query([])?;
                Ok(rows.next()?.is_some())
            }).await?
        } else {
            false
        };
        Ok((up, schema_ok))
    }
}

/// User model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: String,
}

/// Database plugin for the plugin system.
pub struct DatabasePlugin {
    db: Arc<Database>,
}

impl DatabasePlugin {
    /// Create a new database plugin.
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Get database reference.
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }
}

impl crate::plugin::Plugin for DatabasePlugin {
    fn name(&self) -> &'static str {
        "db"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn init(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}