//! Example migrations for the database system.
//!
//! This module demonstrates how to create and use database migrations
//! with the AIVIANIA framework.

use super::{DatabaseConnection, DatabaseError, Migration};

/// Example migration: Create users table
pub struct CreateUsersTable;

impl Migration for CreateUsersTable {
    fn version(&self) -> i64 {
        1
    }

    fn description(&self) -> &'static str {
        "Create users table with basic authentication fields"
    }

    fn up<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        let query = r#"
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                avatar_url VARCHAR(500),
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        "#
        .to_string();

        Box::pin(async move {
            db.execute(&query, vec![]).await?;
            Ok(())
        })
    }

    fn down<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        let query = "DROP TABLE users".to_string();
        Box::pin(async move {
            db.execute(&query, vec![]).await?;
            Ok(())
        })
    }
}

/// Example migration: Add sessions table
pub struct CreateSessionsTable;

impl Migration for CreateSessionsTable {
    fn version(&self) -> i64 {
        2
    }

    fn description(&self) -> &'static str {
        "Create sessions table for session management"
    }

    fn up<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        let query = r#"
            CREATE TABLE sessions (
                id VARCHAR(255) PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        "#
        .to_string();

        Box::pin(async move {
            db.execute(&query, vec![]).await?;
            Ok(())
        })
    }

    fn down<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        let query = "DROP TABLE sessions".to_string();
        Box::pin(async move {
            db.execute(&query, vec![]).await?;
            Ok(())
        })
    }
}

/// Example migration: Add user profile fields
pub struct AddUserProfileFields;

impl Migration for AddUserProfileFields {
    fn version(&self) -> i64 {
        3
    }

    fn description(&self) -> &'static str {
        "Add profile fields to users table"
    }

    fn up<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        // We'll only add columns that don't already exist to make this migration idempotent.
        let queries: Vec<(&str, String)> = vec![
            ("first_name", "ALTER TABLE users ADD COLUMN first_name VARCHAR(100)".to_string()),
            ("last_name", "ALTER TABLE users ADD COLUMN last_name VARCHAR(100)".to_string()),
            ("avatar_url", "ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500)".to_string()),
            ("is_active", "ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE".to_string()),
        ];

        Box::pin(async move {
            // Query existing columns
            let info = db.query("PRAGMA table_info(users)", vec![]).await?;
            let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
            if let crate::database::QueryResult::Query(rows) = info {
                for row in rows {
                    if let Some(serde_json::Value::String(name)) = row.get("name") {
                        existing.insert(name.clone());
                    }
                }
            }

            for (col, query) in queries {
                if !existing.contains(col) {
                    // If column not present, add it
                    let _ = db.execute(&query, vec![]).await?;
                }
            }

            Ok(())
        })
    }

    fn down<'a>(
        &'a self,
        db: &'a dyn DatabaseConnection,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DatabaseError>> + Send + 'a>>
    {
        let queries = vec![
            "ALTER TABLE users DROP COLUMN first_name".to_string(),
            "ALTER TABLE users DROP COLUMN last_name".to_string(),
            "ALTER TABLE users DROP COLUMN avatar_url".to_string(),
            "ALTER TABLE users DROP COLUMN is_active".to_string(),
        ];

        Box::pin(async move {
            for query in queries {
                db.execute(&query, vec![]).await?;
            }
            Ok(())
        })
    }
}

/// Get all example migrations
pub fn get_example_migrations() -> Vec<Box<dyn Migration>> {
    vec![
        Box::new(CreateUsersTable),
        Box::new(CreateSessionsTable),
        Box::new(AddUserProfileFields),
    ]
}
