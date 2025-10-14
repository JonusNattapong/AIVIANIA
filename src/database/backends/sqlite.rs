use std::collections::HashMap;
use async_trait::async_trait;
use serde_json::Value;
use tokio_rusqlite::{Connection, params_from_iter, Row};
use rusqlite;
use crate::database::{DatabaseConnection, DatabaseError, QueryResult};

pub struct SqliteConnection {
    conn: Connection,
}

impl SqliteConnection {
    pub async fn new(database_url: &str) -> Result<Self, DatabaseError> {
        let conn = Connection::open(database_url)
            .await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        Ok(Self { conn })
    }

    fn row_to_hashmap(row: &Row) -> Result<HashMap<String, Value>, rusqlite::Error> {
        let mut result = HashMap::new();
        // Get column count from the row's internal structure
        let column_count = row.as_ref().column_count();

        for i in 0..column_count {
            let column_name = row.as_ref().column_name(i).unwrap_or("");
            let value = match row.get_ref(i).map_err(|e| rusqlite::Error::from(e))? {
                tokio_rusqlite::types::ValueRef::Null => Value::Null,
                tokio_rusqlite::types::ValueRef::Integer(i) => Value::Number(i.into()),
                tokio_rusqlite::types::ValueRef::Real(f) => Value::Number(serde_json::Number::from_f64(f).unwrap()),
                tokio_rusqlite::types::ValueRef::Text(s) => Value::String(String::from_utf8(s.to_vec()).map_err(|_| rusqlite::Error::InvalidQuery)? ),
                tokio_rusqlite::types::ValueRef::Blob(b) => Value::Array(b.iter().map(|&b| Value::Number(b.into())).collect()),
            };
            result.insert(column_name.to_string(), value);
        }
        Ok(result)
    }

    fn convert_params(params: &[Value]) -> Vec<tokio_rusqlite::types::Value> {
        params.iter().map(|param| match param {
            Value::Null => tokio_rusqlite::types::Value::Null,
            Value::Bool(b) => tokio_rusqlite::types::Value::Integer(if *b { 1 } else { 0 }),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    tokio_rusqlite::types::Value::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    tokio_rusqlite::types::Value::Real(f)
                } else {
                    tokio_rusqlite::types::Value::Text(n.to_string())
                }
            }
            Value::String(s) => tokio_rusqlite::types::Value::Text(s.clone()),
            Value::Array(arr) => {
                let bytes: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                tokio_rusqlite::types::Value::Blob(bytes)
            }
            Value::Object(_) => tokio_rusqlite::types::Value::Text(serde_json::to_string(param).unwrap_or_default()),
        }).collect()
    }
}

#[async_trait]
impl DatabaseConnection for SqliteConnection {
    async fn execute(&self, query: &str, params: Vec<Value>) -> Result<QueryResult, DatabaseError> {
        let query = query.to_string();
        let params = Self::convert_params(&params);
        let rows_affected = self.conn.call(move |conn| {
            Ok(conn.execute(&query, params_from_iter(params))?)
        }).await.map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(QueryResult::Execute(rows_affected as u64))
    }

    async fn query(&self, query: &str, params: Vec<Value>) -> Result<QueryResult, DatabaseError> {
        let query = query.to_string();
        let params = Self::convert_params(&params);
        let rows = self.conn.call(move |conn| -> Result<Vec<HashMap<String, Value>>, tokio_rusqlite::Error> {
            let mut stmt = conn.prepare(&query)?;
            let rows = stmt.query_map(params_from_iter(params), |row| {
                Self::row_to_hashmap(row)
            })?;

            let mut results = Vec::new();
            for row_result in rows {
                results.push(row_result?);
            }
            Ok(results)
        }).await.map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(QueryResult::Query(rows))
    }

    async fn query_one(&self, query: &str, params: Vec<Value>) -> Result<QueryResult, DatabaseError> {
        let query = query.to_string();
        let params = Self::convert_params(&params);
        let row = self.conn.call(move |conn| -> Result<Option<HashMap<String, Value>>, tokio_rusqlite::Error> {
            let mut stmt = conn.prepare(&query)?;
            let mut rows = stmt.query_map(params_from_iter(params), |row| {
                Self::row_to_hashmap(row)
            })?;

            if let Some(row_result) = rows.next() {
                Ok(Some(row_result?))
            } else {
                Ok(None)
            }
        }).await.map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(QueryResult::QueryOne(row))
    }

    async fn ping(&self) -> Result<bool, DatabaseError> {
        self.conn.call(|conn| {
            Ok(conn.execute("SELECT 1", [])?)
        }).await.map_err(|e| DatabaseError::QueryError(e.to_string()))?;
        Ok(true)
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        // SQLite connections are automatically closed when dropped
        Ok(())
    }
}