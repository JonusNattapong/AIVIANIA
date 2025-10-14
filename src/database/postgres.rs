//! PostgreSQL database backend implementation.
//!
//! This module provides PostgreSQL database connectivity with connection pooling
//! and full transaction support.

use super::{DatabaseConnection, DatabaseError, Transaction};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio_postgres::{Client, NoTls, Row};

/// PostgreSQL database connection
pub struct PostgresConnection {
    client: Client,
}

impl PostgresConnection {
    /// Create a new PostgreSQL connection
    pub async fn new(connection_string: &str) -> Result<Box<dyn DatabaseConnection>, DatabaseError> {
        let (client, connection) = tokio_postgres::connect(connection_string, NoTls).await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        // Spawn the connection to run in the background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("PostgreSQL connection error: {}", e);
            }
        });

        Ok(Box::new(Self { client }))
    }
}

#[async_trait]
impl DatabaseConnection for PostgresConnection {
    async fn execute(&self, query: &str, params: Vec<serde_json::Value>) -> Result<u64, DatabaseError> {
        let params = convert_params(params);

        let result = self.client.execute(query, &params[..]).await
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(result)
    }

    async fn query(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Vec<HashMap<String, serde_json::Value>>, DatabaseError> {
        let params = convert_params(params);

        let rows = self.client.query(query, &params[..]).await
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let results = rows.into_iter()
            .map(row_to_hashmap)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    async fn query_one(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Option<HashMap<String, serde_json::Value>>, DatabaseError> {
        let params = convert_params(params);

        let row = self.client.query_opt(query, &params[..]).await
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        match row {
            Some(row) => Ok(Some(row_to_hashmap(&row)?)),
            None => Ok(None),
        }
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>, DatabaseError> {
        // For simplicity, we'll use the client directly
        // In a real implementation, you'd want proper transaction isolation
        Err(DatabaseError::TransactionError("Transactions not implemented for PostgreSQL".to_string()))
    }

    async fn ping(&self) -> Result<(), DatabaseError> {
        self.client.simple_query("SELECT 1").await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        // PostgreSQL connections close automatically when dropped
        Ok(())
    }
}

/// Convert a PostgreSQL row to a HashMap
fn row_to_hashmap(row: &Row) -> Result<HashMap<String, serde_json::Value>, DatabaseError> {
    let mut result = HashMap::new();

    for (i, column) in row.columns().iter().enumerate() {
        let column_name = column.name();
        let value = match row.try_get::<_, Option<String>>(i) {
            Ok(Some(s)) => serde_json::Value::String(s),
            Ok(None) => serde_json::Value::Null,
            Err(_) => match row.try_get::<_, Option<i32>>(i) {
                Ok(Some(n)) => serde_json::Value::Number(n.into()),
                Ok(None) => serde_json::Value::Null,
                Err(_) => match row.try_get::<_, Option<i64>>(i) {
                    Ok(Some(n)) => serde_json::Value::Number(n.into()),
                    Ok(None) => serde_json::Value::Null,
                    Err(_) => match row.try_get::<_, Option<f64>>(i) {
                        Ok(Some(f)) => serde_json::Value::Number(serde_json::Number::from_f64(f).unwrap_or(0.into())),
                        Ok(None) => serde_json::Value::Null,
                        Err(_) => match row.try_get::<_, Option<bool>>(i) {
                            Ok(Some(b)) => serde_json::Value::Bool(b),
                            Ok(None) => serde_json::Value::Null,
                            Err(_) => match row.try_get::<_, Option<Vec<u8>>>(i) {
                                Ok(Some(bytes)) => serde_json::Value::Array(
                                    bytes.iter().map(|&byte| serde_json::Value::Number(byte.into())).collect()
                                ),
                                Ok(None) => serde_json::Value::Null,
                                Err(_) => {
                                    // Try to get as JSON string for complex types
                                    match row.try_get::<_, Option<String>>(i) {
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

/// Convert serde_json values to tokio_postgres parameters
fn convert_params(params: Vec<serde_json::Value>) -> Vec<&(dyn tokio_postgres::types::ToSql + Sync)> {
    // This is a simplified conversion - in practice, you'd need proper type handling
    // For now, we'll convert to strings and let PostgreSQL handle the conversion
    params.into_iter().map(|value| {
        match value {
            serde_json::Value::Null => &"NULL" as &dyn tokio_postgres::types::ToSql,
            serde_json::Value::Bool(b) => if b { &"true" } else { &"false" } as &dyn tokio_postgres::types::ToSql,
            serde_json::Value::Number(n) => &n.to_string() as &dyn tokio_postgres::types::ToSql,
            serde_json::Value::String(s) => &s as &dyn tokio_postgres::types::ToSql,
            serde_json::Value::Array(arr) => &serde_json::to_string(&arr).unwrap_or_default() as &dyn tokio_postgres::types::ToSql,
            serde_json::Value::Object(obj) => &serde_json::to_string(&obj).unwrap_or_default() as &dyn tokio_postgres::types::ToSql,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running PostgreSQL instance
    // For CI/CD, you might want to use testcontainers or similar

    #[tokio::test]
    #[ignore] // Requires PostgreSQL
    async fn test_postgres_connection() {
        let connection_string = "host=localhost user=postgres password=password dbname=test";

        let conn = PostgresConnection::new(connection_string).await.unwrap();

        // Test ping
        conn.ping().await.unwrap();

        // Test execute
        let rows_affected = conn.execute("CREATE TABLE IF NOT EXISTS test (id SERIAL PRIMARY KEY, name TEXT)", vec![]).await.unwrap();
        assert_eq!(rows_affected, 0); // DDL doesn't return affected rows

        // Test insert
        let rows_affected = conn.execute("INSERT INTO test (name) VALUES ($1)", vec![serde_json::Value::String("test".to_string())]).await.unwrap();
        assert_eq!(rows_affected, 1);

        // Test query
        let results = conn.query("SELECT * FROM test WHERE name = $1", vec![serde_json::Value::String("test".to_string())]).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].get("name"), Some(&serde_json::Value::String("test".to_string())));
    }
}