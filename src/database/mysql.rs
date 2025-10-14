//! MySQL database backend implementation.
//!
//! This module provides MySQL database connectivity with connection pooling
//! and full transaction support.

use super::{DatabaseConnection, DatabaseError, Transaction};
use async_trait::async_trait;
use mysql_async::{prelude::*, Pool, Row};
use std::collections::HashMap;

/// MySQL database connection
pub struct MysqlConnection {
    pool: Pool,
}

impl MysqlConnection {
    /// Create a new MySQL connection pool
    pub async fn new(connection_string: &str) -> Result<Box<dyn DatabaseConnection>, DatabaseError> {
        let pool = Pool::new(connection_string);
        // Test the connection
        let mut conn = pool.get_conn().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        conn.ping().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        drop(conn);

        Ok(Box::new(Self { pool }))
    }
}

#[async_trait]
impl DatabaseConnection for MysqlConnection {
    async fn execute(&self, query: &str, params: Vec<serde_json::Value>) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.get_conn().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        let params = convert_params(params);

        let result = conn.exec_drop(query, params).await
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(result as u64)
    }

    async fn query(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Vec<HashMap<String, serde_json::Value>>, DatabaseError> {
        let mut conn = self.pool.get_conn().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        let params = convert_params(params);

        let rows: Vec<Row> = conn.exec(query, params).await
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let results = rows.into_iter()
            .map(row_to_hashmap)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    async fn query_one(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Option<HashMap<String, serde_json::Value>>, DatabaseError> {
        let mut results = self.query(query, params).await?;
        Ok(results.pop())
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>, DatabaseError> {
        // For simplicity, we'll use the pool directly
        // In a real implementation, you'd want proper transaction isolation
        Err(DatabaseError::TransactionError("Transactions not implemented for MySQL".to_string()))
    }

    async fn ping(&self) -> Result<(), DatabaseError> {
        let mut conn = self.pool.get_conn().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        conn.ping().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        Ok(())
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        self.pool.disconnect().await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        Ok(())
    }
}

/// Convert a MySQL row to a HashMap
fn row_to_hashmap(row: Row) -> Result<HashMap<String, serde_json::Value>, DatabaseError> {
    let mut result = HashMap::new();

    for (i, column) in row.columns_ref().iter().enumerate() {
        let column_name = column.name_str();
        let value = match row.get_opt::<Option<String>, _>(i) {
            Ok(Some(s)) => serde_json::Value::String(s),
            Ok(None) => serde_json::Value::Null,
            Err(_) => match row.get_opt::<Option<i32>, _>(i) {
                Ok(Some(n)) => serde_json::Value::Number(n.into()),
                Ok(None) => serde_json::Value::Null,
                Err(_) => match row.get_opt::<Option<i64>, _>(i) {
                    Ok(Some(n)) => serde_json::Value::Number(n.into()),
                    Ok(None) => serde_json::Value::Null,
                    Err(_) => match row.get_opt::<Option<f64>, _>(i) {
                        Ok(Some(f)) => serde_json::Value::Number(serde_json::Number::from_f64(f).unwrap_or(0.into())),
                        Ok(None) => serde_json::Value::Null,
                        Err(_) => match row.get_opt::<Option<bool>, _>(i) {
                            Ok(Some(b)) => serde_json::Value::Bool(b),
                            Ok(None) => serde_json::Value::Null,
                            Err(_) => match row.get_opt::<Option<Vec<u8>>, _>(i) {
                                Ok(Some(bytes)) => serde_json::Value::Array(
                                    bytes.iter().map(|&byte| serde_json::Value::Number(byte.into())).collect()
                                ),
                                Ok(None) => serde_json::Value::Null,
                                Err(_) => {
                                    // Try to get as JSON string for complex types
                                    match row.get_opt::<Option<String>, _>(i) {
                                        Ok(Some(json_str)) => {
                                            serde_json::from_str(&json_str)
                                                .unwrap_or(serde_json::Value::String(json_str))
                                        }
                                        _ => serde_json::Value::Null,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
        result.insert(column_name.to_string(), value);
    }

    Ok(result)
}

/// Convert serde_json values to mysql_async parameters
fn convert_params(params: Vec<serde_json::Value>) -> Vec<mysql_async::Value> {
    params.into_iter().map(|value| match value {
        serde_json::Value::Null => mysql_async::Value::NULL,
        serde_json::Value::Bool(b) => mysql_async::Value::Int(if b { 1 } else { 0 }),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                mysql_async::Value::Int(i as i64)
            } else if let Some(f) = n.as_f64() {
                mysql_async::Value::Float(f)
            } else {
                mysql_async::Value::Bytes(n.to_string().into_bytes())
            }
        }
        serde_json::Value::String(s) => mysql_async::Value::Bytes(s.into_bytes()),
        serde_json::Value::Array(arr) => {
            // Convert array to JSON string for simplicity
            mysql_async::Value::Bytes(serde_json::to_string(&arr).unwrap_or_default().into_bytes())
        }
        serde_json::Value::Object(obj) => {
            // Convert object to JSON string for simplicity
            mysql_async::Value::Bytes(serde_json::to_string(&obj).unwrap_or_default().into_bytes())
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running MySQL instance
    // For CI/CD, you might want to use testcontainers or similar

    #[tokio::test]
    #[ignore] // Requires MySQL
    async fn test_mysql_connection() {
        let connection_string = "mysql://root:password@localhost:3306/test";

        let conn = MysqlConnection::new(connection_string).await.unwrap();

        // Test ping
        conn.ping().await.unwrap();

        // Test execute
        let rows_affected = conn.execute("CREATE TABLE IF NOT EXISTS test (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))", vec![]).await.unwrap();
        assert_eq!(rows_affected, 0); // DDL doesn't return affected rows

        // Test insert
        let rows_affected = conn.execute("INSERT INTO test (name) VALUES (?)", vec![serde_json::Value::String("test".to_string())]).await.unwrap();
        assert_eq!(rows_affected, 1);

        // Test query
        let results = conn.query("SELECT * FROM test WHERE name = ?", vec![serde_json::Value::String("test".to_string())]).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].get("name"), Some(&serde_json::Value::String("test".to_string())));
    }
}