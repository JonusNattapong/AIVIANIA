//! Repository implementations for data access patterns.
//!
//! This module demonstrates the repository pattern implementation
//! for common database operations.

use super::{DatabaseConnection, DatabaseError, QueryResult, Repository};
use crate::auth::models::Role;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl User {
    /// Convert to auth::models::User for RBAC operations
    pub fn to_auth_user(&self) -> crate::auth::models::User {
        let role = match self.role.as_str() {
            "admin" => Role::Admin,
            "user" => Role::User,
            "moderator" => Role::Moderator,
            "guest" => Role::Guest,
            custom => Role::Custom(custom.to_string()),
        };

        crate::auth::models::User {
            id: self.id.map(|id| id.to_string()).unwrap_or_default(),
            username: self.username.clone(),
            email: self.email.clone(),
            password_hash: self.password_hash.clone(),
            roles: std::collections::HashSet::from([role]),
            permissions: std::collections::HashSet::new(), // TODO: populate from role
            is_active: self.is_active,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login: None, // TODO: add to database schema if needed
        }
    }
}

/// User repository implementation
pub struct UserRepository<T: DatabaseConnection> {
    db: T,
}

impl<T: DatabaseConnection> UserRepository<T> {
    pub fn new(db: T) -> Self {
        Self { db }
    }
}

#[async_trait]
impl<T: DatabaseConnection + Send + Sync> Repository<User, i64> for UserRepository<T> {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DatabaseError> {
        let query = "SELECT * FROM users WHERE id = ?";
        let params = vec![serde_json::Value::Number(id.into())];

        let result = self.db.query_one(query, params).await?;

        match result {
            QueryResult::QueryOne(Some(row)) => {
                let user = User::from_row(row)?;
                Ok(Some(user))
            }
            QueryResult::QueryOne(None) => Ok(None),
            _ => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<User>, DatabaseError> {
        let query = "SELECT * FROM users ORDER BY created_at DESC";
        let results = self.db.query(query, vec![]).await?;

        match results {
            QueryResult::Query(rows) => {
                let users = rows
                    .into_iter()
                    .map(User::from_row)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(users)
            }
            _ => Ok(vec![]),
        }
    }

    async fn save(&self, entity: User) -> Result<i64, DatabaseError> {
        let query = r#"
            INSERT INTO users (
                username, email, password_hash, role,
                first_name, last_name, avatar_url, is_active,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        let now = chrono::Utc::now();
        let params = vec![
            serde_json::Value::String(entity.username.clone()),
            serde_json::Value::String(entity.email.clone()),
            serde_json::Value::String(entity.password_hash.clone()),
            serde_json::Value::String(entity.role.clone()),
            entity
                .first_name
                .as_ref()
                .map(|s| serde_json::Value::String(s.clone()))
                .unwrap_or(serde_json::Value::Null),
            entity
                .last_name
                .as_ref()
                .map(|s| serde_json::Value::String(s.clone()))
                .unwrap_or(serde_json::Value::Null),
            entity
                .avatar_url
                .as_ref()
                .map(|s| serde_json::Value::String(s.clone()))
                .unwrap_or(serde_json::Value::Null),
            serde_json::Value::Bool(entity.is_active),
            serde_json::Value::String(now.to_rfc3339()),
            serde_json::Value::String(now.to_rfc3339()),
        ];

        match self.db.execute(query, params).await? {
            QueryResult::Execute(rows_affected) => {
                if rows_affected == 0 {
                    return Err(DatabaseError::QueryError(
                        "Failed to create user".to_string(),
                    ));
                }
            }
            _ => {
                return Err(DatabaseError::QueryError(
                    "Failed to create user".to_string(),
                ))
            }
        }

        // Get the created user (assuming auto-increment ID)
        let query = "SELECT * FROM users WHERE username = ? ORDER BY id DESC LIMIT 1";
        let params = vec![serde_json::Value::String(entity.username.clone())];

        match self.db.query_one(query, params).await? {
            QueryResult::QueryOne(Some(row)) => {
                let user = User::from_row(row)?;
                Ok(user.id.unwrap_or(0))
            }
            QueryResult::QueryOne(None) => Err(DatabaseError::QueryError(
                "Failed to retrieve created user".to_string(),
            )),
            _ => Err(DatabaseError::QueryError(
                "Failed to retrieve created user".to_string(),
            )),
        }
    }

    async fn update(&self, entity: User) -> Result<(), DatabaseError> {
        if let Some(id) = entity.id {
            let query = r#"
                UPDATE users SET
                    username = ?, email = ?, password_hash = ?, role = ?,
                    first_name = ?, last_name = ?, avatar_url = ?, is_active = ?,
                    updated_at = ?
                WHERE id = ?
            "#;

            let now = chrono::Utc::now();
            let params = vec![
                serde_json::Value::String(entity.username.clone()),
                serde_json::Value::String(entity.email.clone()),
                serde_json::Value::String(entity.password_hash.clone()),
                serde_json::Value::String(entity.role.clone()),
                entity
                    .first_name
                    .as_ref()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .unwrap_or(serde_json::Value::Null),
                entity
                    .last_name
                    .as_ref()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .unwrap_or(serde_json::Value::Null),
                entity
                    .avatar_url
                    .as_ref()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .unwrap_or(serde_json::Value::Null),
                serde_json::Value::Bool(entity.is_active),
                serde_json::Value::String(now.to_rfc3339()),
                serde_json::Value::Number(id.into()),
            ];

            match self.db.execute(query, params).await? {
                QueryResult::Execute(rows_affected) => {
                    if rows_affected == 0 {
                        return Err(DatabaseError::NotFound);
                    }
                }
                _ => return Err(DatabaseError::NotFound),
            }
        }
        Ok(())
    }

    async fn delete_by_id(&self, id: i64) -> Result<(), DatabaseError> {
        let query = "DELETE FROM users WHERE id = ?";
        let params = vec![serde_json::Value::Number(id.into())];

        match self.db.execute(query, params).await? {
            QueryResult::Execute(rows_affected) => {
                if rows_affected == 0 {
                    return Err(DatabaseError::NotFound);
                }
                Ok(())
            }
            _ => Err(DatabaseError::NotFound),
        }
    }

    async fn exists_by_id(&self, id: i64) -> Result<bool, DatabaseError> {
        let result = self.find_by_id(id).await?;
        Ok(result.is_some())
    }

    async fn count(&self) -> Result<u64, DatabaseError> {
        let query = "SELECT COUNT(*) as count FROM users";
        let result = self.db.query_one(query, vec![]).await?;
        match result {
            QueryResult::QueryOne(Some(row)) => {
                if let Some(serde_json::Value::Number(n)) = row.get("count") {
                    Ok(n.as_u64().unwrap_or(0))
                } else {
                    Ok(0)
                }
            }
            _ => Ok(0),
        }
    }
}

impl User {
    /// Create a new user
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: None,
            username,
            email,
            password_hash,
            role: "user".to_string(),
            first_name: None,
            last_name: None,
            avatar_url: None,
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Convert database row to User struct
    fn from_row(row: HashMap<String, serde_json::Value>) -> Result<Self, DatabaseError> {
        Ok(Self {
            id: extract_i64(&row, "id")?,
            username: extract_string(&row, "username")?,
            email: extract_string(&row, "email")?,
            password_hash: extract_string(&row, "password_hash")?,
            role: extract_string(&row, "role")?,
            first_name: extract_optional_string(&row, "first_name"),
            last_name: extract_optional_string(&row, "last_name"),
            avatar_url: extract_optional_string(&row, "avatar_url"),
            is_active: extract_bool(&row, "is_active")?,
            created_at: extract_datetime(&row, "created_at")?,
            updated_at: extract_datetime(&row, "updated_at")?,
        })
    }
}

/// Helper functions for extracting values from database rows
fn extract_string(
    row: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<String, DatabaseError> {
    match row.get(key) {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        _ => Err(DatabaseError::QueryError(format!(
            "Invalid or missing field: {}",
            key
        ))),
    }
}

fn extract_optional_string(row: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    match row.get(key) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn extract_i64(
    row: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<Option<i64>, DatabaseError> {
    match row.get(key) {
        Some(serde_json::Value::Number(n)) => Ok(n.as_i64()),
        Some(serde_json::Value::Null) => Ok(None),
        _ => Err(DatabaseError::QueryError(format!(
            "Invalid field type for {}: expected number",
            key
        ))),
    }
}

fn extract_bool(
    row: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<bool, DatabaseError> {
    match row.get(key) {
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(serde_json::Value::Number(n)) => Ok(n.as_i64().unwrap_or(0) != 0), // SQLite compatibility
        _ => Err(DatabaseError::QueryError(format!(
            "Invalid field type for {}: expected boolean",
            key
        ))),
    }
}

fn extract_datetime(
    row: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<chrono::DateTime<chrono::Utc>, DatabaseError> {
    match row.get(key) {
        Some(serde_json::Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                DatabaseError::QueryError(format!("Invalid datetime format for {}: {}", key, e))
            }),
        _ => Err(DatabaseError::QueryError(format!(
            "Invalid field type for {}: expected string",
            key
        ))),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "sqlite")]
    use super::*;
    #[cfg(feature = "sqlite")]
    use crate::database::{DatabaseConfig, DatabaseManager, DatabaseType};

    #[tokio::test]
    #[cfg(feature = "sqlite")]
    async fn test_user_repository() {
        use tempfile::NamedTempFile;
        use std::sync::Arc;

        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path().to_str().unwrap();

        let config = DatabaseConfig {
            database_type: DatabaseType::Sqlite,
            connection_string: db_path.to_string(),
            max_connections: 5,
            min_connections: 1,
            connection_timeout: 30,
            acquire_timeout: 30,
            idle_timeout: 300,
            max_lifetime: 3600,
        };

        let db_manager = DatabaseManager::new(config).await.unwrap();

        // Wrap manager in Arc so we can pass Arc<DatabaseManager> which implements DatabaseConnection
        let db = Arc::new(db_manager);

        // Run migrations (migration.up expects a &dyn DatabaseConnection)
        let migrations = crate::database::migrations::get_example_migrations();
        for migration in migrations {
            migration.up(db.connection().as_ref()).await.unwrap();
        }

        // Test repository using Arc<DatabaseManager>
        let repo = UserRepository::new(db.clone());

        // Create user
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
        );
        user.first_name = Some("Test".to_string());
        user.last_name = Some("User".to_string());

        let created_id = repo.save(user.clone()).await.unwrap();
        let created_user = repo.find_by_id(created_id).await.unwrap().unwrap();
        assert_eq!(created_user.username, "testuser");
        assert!(created_user.id.is_some());

        // Update user
        let mut updated_user = created_user.clone();
        updated_user.first_name = Some("Updated".to_string());
        repo.update(updated_user.clone()).await.unwrap();
        let updated = repo.find_by_id(updated_user.id.unwrap()).await.unwrap().unwrap();
        assert_eq!(updated.first_name, Some("Updated".to_string()));

        // Find all users
        let all_users = repo.find_all().await.unwrap();
        assert_eq!(all_users.len(), 1);

        // Delete user
        repo.delete_by_id(updated.id.unwrap()).await.unwrap();

        // Verify deletion
        let deleted_user = repo.find_by_id(updated.id.unwrap()).await.unwrap();
        assert!(deleted_user.is_none());
    }
}
