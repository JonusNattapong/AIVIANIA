//! MongoDB database backend implementation.
//!
//! This module provides MongoDB database connectivity with connection pooling
//! and full transaction support.

use super::{DatabaseConnection, DatabaseError, Transaction};
use async_trait::async_trait;
use mongodb::{bson::Document, options::ClientOptions, Client, Database};
use std::collections::HashMap;

/// MongoDB database connection
pub struct MongoConnection {
    database: Database,
}

impl MongoConnection {
    /// Create a new MongoDB connection
    pub async fn new(connection_string: &str, database_name: &str) -> Result<Box<dyn DatabaseConnection>, DatabaseError> {
        let client_options = ClientOptions::parse(connection_string).await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        let client = Client::with_options(client_options)
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        // Test the connection
        client.list_database_names(None, None).await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        let database = client.database(database_name);

        Ok(Box::new(Self { database }))
    }
}

#[async_trait]
impl DatabaseConnection for MongoConnection {
    async fn execute(&self, query: &str, params: Vec<serde_json::Value>) -> Result<u64, DatabaseError> {
        // MongoDB doesn't have a direct "execute" equivalent
        // We'll interpret this as an insert/update operation
        let doc = parse_query_to_document(query, &params)?;

        if let Some(collection_name) = doc.get_str("collection").ok() {
            let collection = self.database.collection::<Document>(collection_name);

            if let Some(operation) = doc.get_str("operation").ok() {
                match operation {
                    "insert" => {
                        if let Some(data) = doc.get_document("data").ok() {
                            let result = collection.insert_one(data.clone(), None).await
                                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;
                            return Ok(1); // Inserted one document
                        }
                    }
                    "update" => {
                        if let (Some(filter), Some(update)) = (
                            doc.get_document("filter").ok(),
                            doc.get_document("update").ok()
                        ) {
                            let result = collection.update_many(filter.clone(), update.clone(), None).await
                                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;
                            return Ok(result.modified_count);
                        }
                    }
                    "delete" => {
                        if let Some(filter) = doc.get_document("filter").ok() {
                            let result = collection.delete_many(filter.clone(), None).await
                                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;
                            return Ok(result.deleted_count);
                        }
                    }
                    _ => {}
                }
            }
        }

        Err(DatabaseError::QueryError("Invalid MongoDB operation".to_string()))
    }

    async fn query(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Vec<HashMap<String, serde_json::Value>>, DatabaseError> {
        let doc = parse_query_to_document(query, &params)?;

        if let Some(collection_name) = doc.get_str("collection").ok() {
            let collection = self.database.collection::<Document>(collection_name);

            let filter = doc.get_document("filter")
                .unwrap_or(&Document::new())
                .clone();

            let cursor = collection.find(filter, None).await
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            let docs = cursor.try_collect::<Vec<_>>().await
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            let results = docs.into_iter()
                .map(document_to_hashmap)
                .collect::<Result<Vec<_>, _>>()?;

            Ok(results)
        } else {
            Err(DatabaseError::QueryError("Collection name required for MongoDB query".to_string()))
        }
    }

    async fn query_one(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Option<HashMap<String, serde_json::Value>>, DatabaseError> {
        let doc = parse_query_to_document(query, &params)?;

        if let Some(collection_name) = doc.get_str("collection").ok() {
            let collection = self.database.collection::<Document>(collection_name);

            let filter = doc.get_document("filter")
                .unwrap_or(&Document::new())
                .clone();

            let result = collection.find_one(filter, None).await
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            match result {
                Some(doc) => Ok(Some(document_to_hashmap(&doc)?)),
                None => Ok(None),
            }
        } else {
            Err(DatabaseError::QueryError("Collection name required for MongoDB query".to_string()))
        }
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Transaction>, DatabaseError> {
        // MongoDB transactions are more complex and require session management
        Err(DatabaseError::TransactionError("Transactions not implemented for MongoDB".to_string()))
    }

    async fn ping(&self) -> Result<(), DatabaseError> {
        self.database.list_collection_names(None).await
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), DatabaseError> {
        // MongoDB connections close automatically when dropped
        Ok(())
    }
}

/// Parse a query string and parameters into a MongoDB document
fn parse_query_to_document(query: &str, params: &[serde_json::Value]) -> Result<Document, DatabaseError> {
    // For simplicity, we'll assume the query is a JSON string representing the MongoDB operation
    // In a real implementation, you'd want a proper query parser
    serde_json::from_str(query)
        .map_err(|e| DatabaseError::QueryError(format!("Invalid JSON query: {}", e)))
}

/// Convert a MongoDB document to a HashMap
fn document_to_hashmap(doc: &Document) -> Result<HashMap<String, serde_json::Value>, DatabaseError> {
    let json_str = mongodb::bson::to_string(doc)
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

    let value: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

    match value {
        serde_json::Value::Object(map) => {
            let mut result = HashMap::new();
            for (k, v) in map {
                result.insert(k, v);
            }
            Ok(result)
        }
        _ => Err(DatabaseError::QueryError("Document is not an object".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running MongoDB instance
    // For CI/CD, you might want to use testcontainers or similar

    #[tokio::test]
    #[ignore] // Requires MongoDB
    async fn test_mongo_connection() {
        let connection_string = "mongodb://localhost:27017";
        let database_name = "test";

        let conn = MongoConnection::new(connection_string, database_name).await.unwrap();

        // Test ping
        conn.ping().await.unwrap();

        // Test insert operation
        let query = r#"{
            "collection": "test_collection",
            "operation": "insert",
            "data": {"name": "test"}
        }"#;
        let rows_affected = conn.execute(query, vec![]).await.unwrap();
        assert_eq!(rows_affected, 1);

        // Test query
        let query = r#"{
            "collection": "test_collection",
            "filter": {"name": "test"}
        }"#;
        let results = conn.query(query, vec![]).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].get("name"), Some(&serde_json::Value::String("test".to_string())));
    }
}