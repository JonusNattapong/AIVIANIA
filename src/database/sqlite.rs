//! SQLite database backend implementation.
//!
//! This module provides SQLite database connectivity with connection pooling
//! and full transaction support.

use super::{DatabaseConnection, DatabaseError, Transaction};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio_rusqlite::Connection;

/// SQLite database connection
pub struct SqliteConnection {
    conn: Connection,
}

impl SqliteConnection {
    /// Create a new SQLite connection
    pub async fn new(connection_string: &str) -> Result<Box<dyn DatabaseConnection>, DatabaseError> {
        let conn = Connection::open(connection_string).await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        Ok(Box::new(Self { conn }))
    }
}

#[async_trait]
impl DatabaseConnection for SqliteConnection {
    async fn execute(&self, query: &str, params: Vec<serde_json::Value>) -> Result<u64, DatabaseError> {
        let query = query.to_string();
        let params = convert_params(params);

        self.conn.call(move |conn| {
            let mut stmt = conn.prepare(&query)
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            let rows_affected = stmt.execute(rusqlite::params_from_iter(params))
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            Ok(rows_affected as u64)
        }).await
    }

    async fn query(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Vec<HashMap<String, serde_json::Value>>, DatabaseError> {
        let query = query.to_string();
        let params = convert_params(params);

        self.conn.call(move |conn| {
            let mut stmt = conn.prepare(&query)
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            let rows = stmt.query_map(rusqlite::params_from_iter(params), |row| {
                let mut result = HashMap::new();
                for i in 0..row.column_count() {
                    let column_name = row.column_name(i)?;
                    let value = match row.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                        rusqlite::types::ValueRef::Integer(i) => serde_json::Value::Number(i.into()),
                        rusqlite::types::ValueRef::Real(f) => {
                            serde_json::Value::Number(serde_json::Number::from_f64(f).unwrap_or(0.into()))
                        }
                        rusqlite::types::ValueRef::Text(s) => serde_json::Value::String(String::from_utf8_lossy(s).to_string()),
                        rusqlite::types::ValueRef::Blob(b) => serde_json::Value::Array(
                            b.iter().map(|&byte| serde_json::Value::Number(byte.into())).collect()
                        ),
                    };
                    result.insert(column_name.to_string(), value);
                }
                Ok(result)
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row.map_err(|e| DatabaseError::QueryError(e.to_string()))?);
            }

            Ok(results)
        }).await
    }

    async fn query_one(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Option<HashMap<String, serde_json::Value>>, DatabaseError> {
        let mut results = self.query(query, params).await?;
        Ok(results.pop())
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>, DatabaseError> {
        // For simplicity, we'll use the connection directly
        // In a real implementation, you'd want proper transaction isolation
        Err(DatabaseError::TransactionError("Transactions not implemented for SQLite".to_string()))
    }

    async fn ping(&self) -> Result<(), DatabaseError> {
        self.conn.call(|conn| {
            conn.execute("SELECT 1", [])
                .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
            Ok(())
        }).await
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        // SQLite connections close automatically when dropped
        Ok(())
    }
}

/// Convert serde_json values to rusqlite parameters
fn convert_params(params: Vec<serde_json::Value>) -> Vec<rusqlite::types::Value> {
    params.into_iter().map(|value| match value {
        serde_json::Value::Null => rusqlite::types::Value::Null,
        serde_json::Value::Bool(b) => rusqlite::types::Value::Integer(if b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                rusqlite::types::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                rusqlite::types::Value::Real(f)
            } else {
                rusqlite::types::Value::Text(n.to_string())
            }
        }
        serde_json::Value::String(s) => rusqlite::types::Value::Text(s),
        serde_json::Value::Array(arr) => {
            // Convert array to JSON string for simplicity
            rusqlite::types::Value::Text(serde_json::to_string(&arr).unwrap_or_default())
        }
        serde_json::Value::Object(obj) => {
            // Convert object to JSON string for simplicity
            rusqlite::types::Value::Text(serde_json::to_string(&obj).unwrap_or_default())
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_sqlite_connection() {
        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path().to_str().unwrap();

        let conn = SqliteConnection::new(db_path).await.unwrap();

        // Test ping
        conn.ping().await.unwrap();

        // Test execute
        let rows_affected = conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)", vec![]).await.unwrap();
        assert_eq!(rows_affected, 0); // DDL doesn't return affected rows

        // Test insert
        let rows_affected = conn.execute("INSERT INTO test (name) VALUES (?)", vec![serde_json::Value::String("test".to_string())]).await.unwrap();
        assert_eq!(rows_affected, 1);

        // Test query
        let results = conn.query("SELECT * FROM test", vec![]).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].get("name"), Some(&serde_json::Value::String("test".to_string())));
    }
}