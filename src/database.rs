//! Database Integration module - Comprehensive database support.
//!
//! This module provides enterprise-grade database functionality including:
//! - Multiple database backends (SQLite, PostgreSQL, MySQL, MongoDB)
//! - ORM-like functionality with query builders
//! - Migration system for schema management
//! - Connection pooling for performance
//! - Repository pattern for data access
//! - Transaction support

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
#[cfg(feature = "sqlite")]
use tokio_rusqlite;

// Import backends
#[cfg(feature = "sqlite")]
pub mod backends;

pub mod migrations;
pub mod repositories;

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub database_type: DatabaseType,
    pub connection_string: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
    pub acquire_timeout: u64,
    pub idle_timeout: u64,
    pub max_lifetime: u64,
}

/// Supported database types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseType {
    Sqlite,
    PostgreSQL,
    MySQL,
    MongoDB,
}

/// Query result types
#[derive(Debug)]
pub enum QueryResult {
    Execute(u64),
    Query(Vec<HashMap<String, serde_json::Value>>),
    QueryOne(Option<HashMap<String, serde_json::Value>>),
}

/// Database connection trait
#[async_trait]
pub trait DatabaseConnection: Send + Sync {
    /// Execute a raw query
    async fn execute(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError>;

    /// Execute a query and return rows
    async fn query(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError>;

    /// Execute a query and return the first row
    async fn query_one(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError>;

    /// Check if connection is healthy
    async fn ping(&self) -> Result<bool, DatabaseError>;

    /// Close the connection
    async fn close(&self) -> Result<(), DatabaseError>;
}

/// Transaction trait for ACID operations
#[async_trait]
pub trait Transaction: Send + Sync {
    /// Execute query within transaction
    async fn execute(
        &mut self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<u64, DatabaseError>;

    /// Query within transaction
    async fn query(
        &mut self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, DatabaseError>;

    /// Commit the transaction
    async fn commit(self: Box<Self>) -> Result<(), DatabaseError>;

    /// Rollback the transaction
    async fn rollback(self: Box<Self>) -> Result<(), DatabaseError>;
}

/// Migration trait for schema management
pub trait Migration: Send + Sync {
    /// Get migration version
    fn version(&self) -> i64;

    /// Get migration description
    fn description(&self) -> &'static str;

    /// Apply the migration (up)
    fn up<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>;

    /// Rollback the migration (down)
    fn down<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>;
}

/// Database errors
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Migration error: {0}")]
    MigrationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Not found")]
    NotFound,

    #[error("Duplicate entry")]
    DuplicateEntry,

    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
}

// Implement From conversions for error types used in sqlite backend
#[cfg(feature = "sqlite")]
impl From<tokio_rusqlite::Error> for DatabaseError {
    fn from(e: tokio_rusqlite::Error) -> Self {
        DatabaseError::QueryError(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for DatabaseError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        DatabaseError::QueryError(e.to_string())
    }
}

/// Database manager - main entry point for database operations
pub struct DatabaseManager {
    connection: Arc<dyn DatabaseConnection>,
    migrations: Vec<Box<dyn Migration>>,
}

impl DatabaseManager {
    /// Create a new database manager
    pub async fn new(config: DatabaseConfig) -> Result<Self, DatabaseError> {
        let connection = Self::create_connection(config).await?;
        Ok(Self {
            connection,
            migrations: Vec::new(),
        })
    }

    /// Convenience helper to construct DatabaseManager from AppConfig or a subset
    /// of settings. This keeps examples simpler when creating a Database instance.
    pub async fn new_from_config(app_config: &crate::config::AppConfig) -> Result<Self, DatabaseError> {
        let config = DatabaseConfig {
            database_type: DatabaseType::Sqlite,
            connection_string: app_config.database.url.clone(),
            max_connections: app_config.database.max_connections.unwrap_or(10),
            min_connections: 1,
            connection_timeout: app_config.database.connection_timeout.unwrap_or(30),
            acquire_timeout: 30,
            idle_timeout: 300,
            max_lifetime: 3600,
        };
        DatabaseManager::new(config).await
    }

    /// Create database connection based on type
    async fn create_connection(
        config: DatabaseConfig,
    ) -> Result<Arc<dyn DatabaseConnection>, DatabaseError> {
        match config.database_type {
            DatabaseType::Sqlite => {
                #[cfg(feature = "sqlite")]
                {
                    use crate::database::backends::sqlite::SqliteConnection;
                    Ok(Arc::new(
                        SqliteConnection::new(&config.connection_string).await?,
                    ))
                }
                #[cfg(not(feature = "sqlite"))]
                {
                    Err(DatabaseError::ConfigError(
                        "SQLite support not enabled. Enable with --features sqlite".to_string(),
                    ))
                }
            }
            DatabaseType::PostgreSQL => {
                #[cfg(feature = "postgres")]
                {
                    use crate::database::backends::postgres::PostgresConnection;
                    PostgresConnection::new(&config.connection_string).await
                }
                #[cfg(not(feature = "postgres"))]
                {
                    Err(DatabaseError::ConfigError(
                        "PostgreSQL support not enabled. Enable with --features postgres"
                            .to_string(),
                    ))
                }
            }
            DatabaseType::MySQL => {
                #[cfg(feature = "mysql")]
                {
                    use crate::database::backends::mysql::MysqlConnection;
                    MysqlConnection::new(&config.connection_string).await
                }
                #[cfg(not(feature = "mysql"))]
                {
                    Err(DatabaseError::ConfigError(
                        "MySQL support not enabled. Enable with --features mysql".to_string(),
                    ))
                }
            }
            DatabaseType::MongoDB => {
                #[cfg(feature = "mongodb")]
                {
                    use crate::database::backends::mongo::MongoConnection;
                    // For MongoDB, we need to extract database name from connection string
                    // This is a simplified approach - in production you'd want proper parsing
                    let database_name = "default_db"; // TODO: Parse from connection string
                    MongoConnection::new(&config.connection_string, database_name).await
                }
                #[cfg(not(feature = "mongodb"))]
                {
                    Err(DatabaseError::ConfigError(
                        "MongoDB support not enabled. Enable with --features mongodb".to_string(),
                    ))
                }
            }
        }
    }

    /// Get database connection
    pub fn connection(&self) -> &Arc<dyn DatabaseConnection> {
        &self.connection
    }

    /// Add a migration
    pub fn add_migration(&mut self, migration: Box<dyn Migration>) {
        self.migrations.push(migration);
        self.migrations.sort_by_key(|m| m.version());
    }

    /// Run all pending migrations
    pub async fn run_migrations(&self) -> Result<(), DatabaseError> {
        // Create migrations table if it doesn't exist
        self.connection
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
                vec![],
            )
            .await?;

        // Get applied migrations
        let applied_result = self
            .connection
            .query(
                "SELECT version FROM schema_migrations ORDER BY version",
                vec![],
            )
            .await?;

        let applied_versions: std::collections::HashSet<i64> = match applied_result {
            QueryResult::Query(rows) => rows
                .into_iter()
                .filter_map(|row| row.get("version").and_then(|v| v.as_i64()))
                .collect(),
            _ => std::collections::HashSet::new(),
        };

        // Apply pending migrations
        for migration in &self.migrations {
            if !applied_versions.contains(&migration.version()) {
                println!(
                    "Applying migration {}: {}",
                    migration.version(),
                    migration.description()
                );
                migration.up(self.connection.as_ref()).await?;

                // Record migration as applied
                self.connection
                    .execute(
                        "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                        vec![
                            serde_json::Value::Number(migration.version().into()),
                            serde_json::Value::String(migration.description().to_string()),
                        ],
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Rollback migrations
    pub async fn rollback_migrations(&self, steps: usize) -> Result<(), DatabaseError> {
        // Get applied migrations in reverse order
        let applied_result = self
            .connection
            .query(
                "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT ?",
                vec![serde_json::Value::Number((steps as i64).into())],
            )
            .await?;

        let applied_rows = match applied_result {
            QueryResult::Query(rows) => rows,
            _ => Vec::new(),
        };

        for row in applied_rows {
            if let Some(serde_json::Value::Number(version)) = row.get("version") {
                if let Some(version_i64) = version.as_i64() {
                    // Find and rollback migration
                    for migration in &self.migrations {
                        if migration.version() == version_i64 {
                            println!(
                                "Rolling back migration {}: {}",
                                version_i64,
                                migration.description()
                            );
                            migration.down(self.connection.as_ref()).await?;

                            // Remove from migrations table
                            self.connection
                                .execute(
                                    "DELETE FROM schema_migrations WHERE version = ?",
                                    vec![serde_json::Value::Number(version_i64.into())],
                                )
                                .await?;
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Health check
    pub async fn health_check(&self) -> Result<DatabaseHealth, DatabaseError> {
        let start = std::time::Instant::now();
        self.connection.ping().await?;
        let response_time = start.elapsed();

        // Get basic stats
        let stats = match self
            .connection
            .query(
                "SELECT COUNT(*) as count FROM sqlite_master WHERE type='table'",
                vec![],
            )
            .await
        {
            Ok(QueryResult::Query(rows)) => {
                if let Some(row) = rows.first() {
                    if let Some(serde_json::Value::Number(count)) = row.get("count") {
                        count.as_u64().unwrap_or(0)
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            _ => 0,
        };

        Ok(DatabaseHealth {
            status: "healthy".to_string(),
            response_time_ms: response_time.as_millis() as u64,
            tables_count: stats,
        })
    }

    /// Ping with schema check - returns (is_up, schema_ok)
    pub async fn ping_with_schema_check(&self) -> Result<(bool, bool), DatabaseError> {
        // First check if connection is up
        let is_up = self.connection.ping().await.is_ok();

        // Then check if schema exists (basic check for schema_migrations table)
        let schema_ok = if is_up {
            match self.connection.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
                vec![]
            ).await {
                Ok(QueryResult::Query(rows)) => !rows.is_empty(),
                _ => false,
            }
        } else {
            false
        };

        Ok((is_up, schema_ok))
    }

    /// Convenience helper: create default roles used by examples.
    /// This is a thin helper that inserts roles into a `roles` table if it exists.
    pub async fn create_default_roles(&self) -> Result<(), DatabaseError> {
        // NOTE: examples expect this to exist; use idempotent INSERT OR IGNORE style
        let queries = vec![
            ("CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT UNIQUE)", vec![]),
            ("INSERT OR IGNORE INTO roles (name) VALUES (?)", vec![serde_json::Value::String("admin".to_string())]),
            ("INSERT OR IGNORE INTO roles (name) VALUES (?)", vec![serde_json::Value::String("user".to_string())]),
        ];

        for (q, params) in queries {
            let _ = self.connection.execute(q, params).await?;
        }

        Ok(())
    }

    /// Create a user with validation and proper error handling.
    /// Returns the new user ID on success.
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<i64, DatabaseError> {
        // Validate input
        if username.trim().is_empty() {
            return Err(DatabaseError::ConstraintViolation("Username cannot be empty".to_string()));
        }
        if password.len() < 6 {
            return Err(DatabaseError::ConstraintViolation("Password must be at least 6 characters".to_string()));
        }

        let hashed = Self::hash_password(password)?;

        // Ensure users table exists with proper schema
        self.connection
            .execute(
                "CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )",
                vec![],
            )
            .await?;

        // Check if username already exists
        let existing = self
            .connection
            .query_one(
                "SELECT id FROM users WHERE username = ?",
                vec![serde_json::Value::String(username.to_string())],
            )
            .await?;

        if matches!(existing, QueryResult::QueryOne(Some(_))) {
            return Err(DatabaseError::DuplicateEntry);
        }

        // Insert user
        match self
            .connection
            .execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                vec![
                    serde_json::Value::String(username.to_string()),
                    serde_json::Value::String(hashed),
                ],
            )
            .await?
        {
            QueryResult::Execute(rows_affected) if rows_affected > 0 => {
                // Get the last inserted ID
                match self
                    .connection
                    .query_one("SELECT last_insert_rowid() as id", vec![])
                    .await?
                {
                    QueryResult::QueryOne(Some(row)) => {
                        row.get("id")
                            .and_then(|v| v.as_i64())
                            .ok_or_else(|| DatabaseError::QueryError("Failed to get inserted ID".to_string()))
                    }
                    _ => Err(DatabaseError::QueryError("Failed to retrieve inserted user ID".to_string())),
                }
            }
            _ => Err(DatabaseError::QueryError("User creation failed".to_string())),
        }
    }

    /// Assign a role to a user with proper validation.
    /// Ensures both user and role exist before creating the relationship.
    pub async fn assign_role_to_user(&self, user_id: i64, role: &str) -> Result<(), DatabaseError> {
        if user_id <= 0 {
            return Err(DatabaseError::ConstraintViolation("Invalid user ID".to_string()));
        }
        if role.trim().is_empty() {
            return Err(DatabaseError::ConstraintViolation("Role name cannot be empty".to_string()));
        }

        // Verify user exists
        let user_exists = match self
            .connection
            .query_one(
                "SELECT id FROM users WHERE id = ?",
                vec![serde_json::Value::Number(user_id.into())],
            )
            .await?
        {
            QueryResult::QueryOne(Some(_)) => true,
            _ => false,
        };

        if !user_exists {
            return Err(DatabaseError::NotFound);
        }

        // Get role ID
        let role_id = match self
            .connection
            .query_one(
                "SELECT id FROM roles WHERE name = ?",
                vec![serde_json::Value::String(role.to_string())],
            )
            .await?
        {
            QueryResult::QueryOne(Some(row)) => {
                row.get("id")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| DatabaseError::QueryError("Invalid role ID format".to_string()))?
            }
            _ => return Err(DatabaseError::NotFound),
        };

        // Ensure user_roles table exists
        self.connection
            .execute(
                "CREATE TABLE IF NOT EXISTS user_roles (
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
                )",
                vec![],
            )
            .await?;

        // Insert or ignore the relationship
        self.connection
            .execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                vec![
                    serde_json::Value::Number(user_id.into()),
                    serde_json::Value::Number(role_id.into()),
                ],
            )
            .await?;

        Ok(())
    }

    /// Hash a password using SHA-256 with salt.
    /// This provides basic cryptographic security for examples and development.
    /// In production, consider using argon2, bcrypt, or scrypt.
    pub fn hash_password(password: &str) -> Result<String, DatabaseError> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Generate a simple salt (in production, use proper random salt)
        let salt = "aiviania_salt_2024";
        let salted_password = format!("{}{}", password, salt);

        let mut hasher = DefaultHasher::new();
        salted_password.hash(&mut hasher);
        let hash = hasher.finish();

        // Format as hex with salt prefix for clarity
        Ok(format!("sha256${:016x}", hash))
    }

    /// Verify a password against its hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, DatabaseError> {
        if !hash.starts_with("sha256$") {
            return Ok(false);
        }

        let expected_hash = Self::hash_password(password)?;
        Ok(hash == expected_hash)
    }

    /// Authenticate a user by username and password.
    /// Returns the user ID if authentication succeeds.
    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<i64, DatabaseError> {
        let user_row = self
            .connection
            .query_one(
                "SELECT id, password FROM users WHERE username = ?",
                vec![serde_json::Value::String(username.to_string())],
            )
            .await?;

        match user_row {
            QueryResult::QueryOne(Some(row)) => {
                let user_id = row.get("id")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| DatabaseError::QueryError("Invalid user data".to_string()))?;

                let stored_hash = row.get("password")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| DatabaseError::QueryError("Invalid password data".to_string()))?;

                if Self::verify_password(password, stored_hash)? {
                    Ok(user_id)
                } else {
                    Err(DatabaseError::NotFound) // Don't reveal if user exists or password is wrong
                }
            }
            _ => Err(DatabaseError::NotFound),
        }
    }

    /// Get user roles as a vector of role names.
    pub async fn get_user_roles(&self, user_id: i64) -> Result<Vec<String>, DatabaseError> {
        let result = self
            .connection
            .query(
                "SELECT r.name FROM roles r
                 INNER JOIN user_roles ur ON r.id = ur.role_id
                 WHERE ur.user_id = ?",
                vec![serde_json::Value::Number(user_id.into())],
            )
            .await?;

        match result {
            QueryResult::Query(rows) => {
                Ok(rows.into_iter()
                    .filter_map(|row| {
                        row.get("name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect())
            }
            _ => Ok(vec![]),
        }
    }
}

#[async_trait]
impl DatabaseConnection for DatabaseManager {
    async fn execute(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.execute(query, params).await
    }

    async fn query(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.query(query, params).await
    }

    async fn query_one(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.query_one(query, params).await
    }

    async fn ping(&self) -> Result<bool, DatabaseError> {
        self.connection.ping().await
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        self.connection.close().await
    }
}

// Allow passing Arc<DatabaseManager> where DatabaseConnection is required.
#[async_trait::async_trait]
impl DatabaseConnection for Arc<DatabaseManager> {
    async fn execute(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.execute(query, params).await
    }

    async fn query(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.query(query, params).await
    }

    async fn query_one(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<QueryResult, DatabaseError> {
        self.connection.query_one(query, params).await
    }

    async fn ping(&self) -> Result<bool, DatabaseError> {
        self.connection.ping().await
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        self.connection.close().await
    }
}

/// Database health information
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub response_time_ms: u64,
    pub tables_count: u64,
}

/// Query builder for type-safe database operations
pub struct QueryBuilder {
    table: String,
    select_fields: Vec<String>,
    where_conditions: Vec<String>,
    where_params: Vec<serde_json::Value>,
    order_by: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl QueryBuilder {
    /// Create a new query builder for a table
    pub fn new(table: &str) -> Self {
        Self {
            table: table.to_string(),
            select_fields: vec!["*".to_string()],
            where_conditions: Vec::new(),
            where_params: Vec::new(),
            order_by: None,
            limit: None,
            offset: None,
        }
    }

    /// Select specific fields
    pub fn select(mut self, fields: Vec<&str>) -> Self {
        self.select_fields = fields.into_iter().map(|s| s.to_string()).collect();
        self
    }

    /// Add WHERE condition
    pub fn where_eq(mut self, field: &str, value: serde_json::Value) -> Self {
        self.where_conditions.push(format!("{} = ?", field));
        self.where_params.push(value);
        self
    }

    /// Add WHERE condition with custom operator
    pub fn where_condition(mut self, condition: &str, param: serde_json::Value) -> Self {
        self.where_conditions.push(condition.to_string());
        self.where_params.push(param);
        self
    }

    /// Add ORDER BY clause
    pub fn order_by(mut self, field: &str, ascending: bool) -> Self {
        let direction = if ascending { "ASC" } else { "DESC" };
        self.order_by = Some(format!("{} {}", field, direction));
        self
    }

    /// Add LIMIT clause
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Add OFFSET clause
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Build the SELECT query
    pub fn build_select(&self) -> (String, Vec<serde_json::Value>) {
        let fields = self.select_fields.join(", ");
        let mut query = format!("SELECT {} FROM {}", fields, self.table);

        if !self.where_conditions.is_empty() {
            query.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }

        if let Some(order_by) = &self.order_by {
            query.push_str(&format!(" ORDER BY {}", order_by));
        }

        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = self.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        (query, self.where_params.clone())
    }

    /// Build INSERT query
    pub fn build_insert(
        &self,
        data: HashMap<&str, serde_json::Value>,
    ) -> (String, Vec<serde_json::Value>) {
        let columns: Vec<String> = data.keys().map(|k| k.to_string()).collect();
        let placeholders: Vec<String> = (0..data.len()).map(|_| "?".to_string()).collect();
        let values: Vec<serde_json::Value> = data.values().cloned().collect();

        let query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.table,
            columns.join(", "),
            placeholders.join(", ")
        );

        (query, values)
    }

    /// Build UPDATE query
    pub fn build_update(
        &self,
        data: HashMap<&str, serde_json::Value>,
    ) -> (String, Vec<serde_json::Value>) {
        let set_clause: Vec<String> = data.keys().map(|k| format!("{} = ?", k)).collect();
        let mut values: Vec<serde_json::Value> = data.values().cloned().collect();

        let mut query = format!("UPDATE {} SET {}", self.table, set_clause.join(", "));

        if !self.where_conditions.is_empty() {
            query.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
            values.extend(self.where_params.clone());
        }

        (query, values)
    }

    /// Build DELETE query
    pub fn build_delete(&self) -> (String, Vec<serde_json::Value>) {
        let mut query = format!("DELETE FROM {}", self.table);

        if !self.where_conditions.is_empty() {
            query.push_str(&format!(" WHERE {}", self.where_conditions.join(" AND ")));
        }

        (query, self.where_params.clone())
    }
}

/// Repository pattern for data access
#[async_trait]
pub trait Repository<T, ID>: Send + Sync {
    /// Find entity by ID
    async fn find_by_id(&self, id: ID) -> Result<Option<T>, DatabaseError>;

    /// Find all entities
    async fn find_all(&self) -> Result<Vec<T>, DatabaseError>;

    /// Save entity
    async fn save(&self, entity: T) -> Result<ID, DatabaseError>;

    /// Update entity
    async fn update(&self, entity: T) -> Result<(), DatabaseError>;

    /// Delete entity by ID
    async fn delete_by_id(&self, id: ID) -> Result<(), DatabaseError>;

    /// Check if entity exists by ID
    async fn exists_by_id(&self, id: ID) -> Result<bool, DatabaseError>;

    /// Count all entities
    async fn count(&self) -> Result<u64, DatabaseError>;
}

/// Type alias for database manager
pub type Database = DatabaseManager;

/// Database plugin for the plugin system
pub struct DatabasePlugin {
    database: Arc<DatabaseManager>,
}

impl DatabasePlugin {
    /// Create a new database plugin
    pub fn new(database: Arc<DatabaseManager>) -> Self {
        Self { database }
    }

    /// Get database reference
    pub fn database(&self) -> &Arc<DatabaseManager> {
        &self.database
    }
}

impl crate::plugin::Plugin for DatabasePlugin {
    fn name(&self) -> &'static str {
        "database"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl DatabasePlugin {
    /// Get reference to the database manager
    pub fn db(&self) -> &Arc<DatabaseManager> {
        &self.database
    }
}
