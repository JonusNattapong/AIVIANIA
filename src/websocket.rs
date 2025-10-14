//! WebSocket module - Real-time communication support.
//!
//! This module provides WebSocket server functionality for real-time bidirectional
//! communication between clients and the server. Features include:
//! - Room-based messaging for chat applications
//! - User-specific messaging
//! - JSON message handling
//! - Connection management with heartbeats
//! - Broadcasting capabilities

use base64::{engine::general_purpose, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hyper::{Body, Request, Response, StatusCode};
use hyper::header::{CONNECTION, UPGRADE};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;

/// WebSocket message types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WSMessage {
    /// Join a room
    Join { room: String },
    /// Leave a room
    Leave { room: String },
    /// Send message to room
    RoomMessage { room: String, message: String },
    /// Send private message to user
    PrivateMessage { user_id: String, message: String },
    /// Broadcast message to all connections
    Broadcast { message: String },
    /// Ping message for heartbeat
    Ping,
    /// Pong response
    Pong,
    /// Error message
    Error { message: String },
}

/// WebSocket connection information
#[derive(Debug, Clone)]
pub struct WSConnection {
    pub id: String,
    pub user_id: Option<String>,
    pub rooms: Vec<String>,
    pub sender: mpsc::UnboundedSender<String>,
}

/// Room-based WebSocket manager
pub struct WebSocketManager {
    connections: Arc<Mutex<HashMap<String, WSConnection>>>,
    rooms: Arc<Mutex<HashMap<String, Vec<String>>>>, // room -> connection_ids
    supported_subprotocols: Vec<String>,
    support_permessage_deflate: bool,
}

impl WebSocketManager {
    /// Create a new WebSocket manager
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            rooms: Arc::new(Mutex::new(HashMap::new())),
            supported_subprotocols: vec!["chat".to_string(), "json".to_string()],
            support_permessage_deflate: true,
        }
    }

    /// Handle WebSocket upgrade request
    pub async fn handle_upgrade(
        &self,
        mut request: Request<Body>,
        user_id: Option<String>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        // Quick validation for websocket upgrade
        let headers = request.headers();
        let upgrade_hdr = headers.get(UPGRADE).and_then(|h| h.to_str().ok()).map(|s| s.to_ascii_lowercase());
        let connection_hdr = headers.get(CONNECTION).and_then(|h| h.to_str().ok()).map(|s| s.to_ascii_lowercase());
        let sec_key = headers.get("sec-websocket-key");

        if upgrade_hdr.as_deref() != Some("websocket") ||
            connection_hdr.as_deref().map(|s| s.contains("upgrade")).unwrap_or(false) == false ||
            sec_key.is_none() {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Expected WebSocket upgrade request"))?);
        }

        // Subprotocol negotiation
        let mut chosen_subprotocol: Option<String> = None;
        if let Some(proto_header) = headers.get("sec-websocket-protocol") {
            if let Ok(proto_str) = proto_header.to_str() {
                let requested: Vec<&str> = proto_str.split(',').map(|s| s.trim()).collect();
                for p in requested {
                    if self.supported_subprotocols.iter().any(|sp| sp == p) {
                        chosen_subprotocol = Some(p.to_string());
                        break;
                    }
                }
            }
        }

        // Extensions negotiation (permessage-deflate)
        let mut extensions_response: Option<String> = None;
        if let Some(ext_header) = headers.get("sec-websocket-extensions") {
            if let Ok(ext_str) = ext_header.to_str() {
                if self.support_permessage_deflate && ext_str.contains("permessage-deflate") {
                    extensions_response = Some("permessage-deflate".to_string());
                }
            }
        }

        // Compute accept key
        let key = sec_key.unwrap().as_bytes();
        let accept_key = self.calculate_accept_key(key);

        // Build response
        let mut builder = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header("sec-websocket-accept", accept_key);

        if let Some(p) = &chosen_subprotocol {
            builder = builder.header("sec-websocket-protocol", p.as_str());
        }

        if let Some(ext) = &extensions_response {
            builder = builder.header("sec-websocket-extensions", ext.as_str());
        }

        let response = builder.body(Body::empty())?;

        // Upgrade and spawn connection handler
        if let Some(on_upgrade) = request.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() {
            let manager = self.clone_manager();
            let user_id_clone = user_id.clone();
            tokio::spawn(async move {
                match on_upgrade.await {
                    Ok(upgraded) => {
                        if let Some(p) = chosen_subprotocol {
                            println!("Negotiated subprotocol: {}", p);
                        }

                        let ws_stream = WebSocketStream::from_raw_socket(
                            upgraded,
                            tokio_tungstenite::tungstenite::protocol::Role::Server,
                            None,
                        ).await;

                        Self::handle_connection(ws_stream, manager, user_id_clone).await;
                    }
                    Err(e) => eprintln!("WebSocket upgrade error: {:?}", e),
                }
            });
        }

        Ok(response)
    }

    /// Handle individual WebSocket connection
    async fn handle_connection(
        ws_stream: WebSocketStream<hyper::upgrade::Upgraded>,
        manager: Arc<WebSocketManager>,
        user_id: Option<String>,
    ) {
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let conn_id = format!("conn_{}", uuid::Uuid::new_v4().simple());

        // Create connection info
        let connection = WSConnection {
            id: conn_id.clone(),
            user_id: user_id.clone(),
            rooms: Vec::new(),
            sender: tx,
        };

        // Add to connections
        {
            let mut conns = manager.connections.lock().await;
            conns.insert(conn_id.clone(), connection);
        }

        let (write, read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        // Task to send messages
        let write_clone = Arc::clone(&write);
        let send_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let mut write_guard = write_clone.lock().await;
                if write_guard.send(tokio_tungstenite::tungstenite::Message::Text(msg)).await.is_err() {
                    break;
                }
            }
        });

        // Task to receive messages
        let manager_clone = manager.clone();
        let conn_id_clone = conn_id.clone();
        let write_clone = Arc::clone(&write);
        let recv_task = tokio::spawn(async move {
            let mut read = read;
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                        if let Err(e) = manager_clone.handle_message(&conn_id_clone, &text).await {
                            eprintln!("Error handling WebSocket message: {:?}", e);
                        }
                    }
                    Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                    Ok(tokio_tungstenite::tungstenite::Message::Ping(data)) => {
                        let mut write_guard = write_clone.lock().await;
                        if write_guard.send(tokio_tungstenite::tungstenite::Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });

        // Wait for either task to finish
        tokio::select! {
            _ = send_task => {},
            _ = recv_task => {},
        }

        // Clean up connection
        manager.remove_connection(&conn_id).await;
    }

    /// Handle incoming WebSocket message
    async fn handle_message(&self, conn_id: &str, text: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let message: WSMessage = serde_json::from_str(text)?;

        match message {
            WSMessage::Join { room } => {
                self.join_room(conn_id, &room).await?;
                self.send_to_connection(conn_id, &serde_json::json!({
                    "type": "joined",
                    "room": room
                }).to_string()).await?;
            }
            WSMessage::Leave { room } => {
                self.leave_room(conn_id, &room).await?;
                self.send_to_connection(conn_id, &serde_json::json!({
                    "type": "left",
                    "room": room
                }).to_string()).await?;
            }
            WSMessage::RoomMessage { room, message } => {
                self.broadcast_to_room(&room, &serde_json::json!({
                    "type": "room_message",
                    "room": room,
                    "from": conn_id,
                    "message": message
                }).to_string(), Some(conn_id)).await?;
            }
            WSMessage::PrivateMessage { user_id, message } => {
                self.send_to_user(&user_id, &serde_json::json!({
                    "type": "private_message",
                    "from": conn_id,
                    "message": message
                }).to_string()).await?;
            }
            WSMessage::Broadcast { message } => {
                self.broadcast(&serde_json::json!({
                    "type": "broadcast",
                    "from": conn_id,
                    "message": message
                }).to_string()).await?;
            }
            WSMessage::Ping => {
                self.send_to_connection(conn_id, &serde_json::json!({
                    "type": "pong"
                }).to_string()).await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Join a room
    async fn join_room(&self, conn_id: &str, room: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rooms = self.rooms.lock().await;
        let room_members = rooms.entry(room.to_string()).or_insert_with(Vec::new);

        if !room_members.contains(&conn_id.to_string()) {
            room_members.push(conn_id.to_string());
        }

        // Update connection's rooms
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get_mut(conn_id) {
            if !conn.rooms.contains(&room.to_string()) {
                conn.rooms.push(room.to_string());
            }
        }

        Ok(())
    }

    /// Leave a room
    async fn leave_room(&self, conn_id: &str, room: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rooms = self.rooms.lock().await;
        if let Some(room_members) = rooms.get_mut(room) {
            room_members.retain(|id| id != conn_id);
            if room_members.is_empty() {
                rooms.remove(room);
            }
        }

        // Update connection's rooms
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get_mut(conn_id) {
            conn.rooms.retain(|r| r != room);
        }

        Ok(())
    }

    /// Send message to specific connection
    async fn send_to_connection(&self, conn_id: &str, message: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conns = self.connections.lock().await;
        if let Some(conn) = conns.get(conn_id) {
            let _ = conn.sender.send(message.to_string());
        }
        Ok(())
    }

    /// Send message to user by user_id
    async fn send_to_user(&self, user_id: &str, message: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conns = self.connections.lock().await;
        for conn in conns.values() {
            if conn.user_id.as_ref() == Some(&user_id.to_string()) {
                let _ = conn.sender.send(message.to_string());
            }
        }
        Ok(())
    }

    /// Broadcast message to all connections
    pub async fn broadcast(&self, message: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let conns = self.connections.lock().await;
        for conn in conns.values() {
            let _ = conn.sender.send(message.to_string());
        }
        Ok(())
    }

    /// Broadcast message to room (optionally excluding a connection)
    pub async fn broadcast_to_room(&self, room: &str, message: &str, exclude_conn: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rooms = self.rooms.lock().await;
        if let Some(room_members) = rooms.get(room) {
            let conns = self.connections.lock().await;
            for conn_id in room_members {
                if Some(conn_id.as_str()) != exclude_conn {
                    if let Some(conn) = conns.get(conn_id) {
                        let _ = conn.sender.send(message.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Remove connection and clean up
    async fn remove_connection(&self, conn_id: &str) {
        // Remove from all rooms
        let mut rooms = self.rooms.lock().await;
        for room_members in rooms.values_mut() {
            room_members.retain(|id| id != conn_id);
        }
        // Remove empty rooms
        rooms.retain(|_, members| !members.is_empty());

        // Remove connection
        let mut conns = self.connections.lock().await;
        conns.remove(conn_id);
    }

    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Get room count
    pub async fn room_count(&self) -> usize {
        self.rooms.lock().await.len()
    }

    /// Clone the manager (for spawning tasks)
    fn clone_manager(&self) -> Arc<WebSocketManager> {
        Arc::new(WebSocketManager {
            connections: Arc::clone(&self.connections),
            rooms: Arc::clone(&self.rooms),
            supported_subprotocols: self.supported_subprotocols.clone(),
            support_permessage_deflate: self.support_permessage_deflate,
        })
    }

    /// Calculate WebSocket accept key
    fn calculate_accept_key(&self, key: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(key);
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let result = hasher.finalize();
        general_purpose::STANDARD.encode(&result)
    }
}


/// WebSocket plugin for the plugin system.
pub struct WebSocketPlugin {
    manager: Arc<WebSocketManager>,
}

impl WebSocketPlugin {
    /// Create a new WebSocket plugin.
    pub fn new() -> Self {
        let manager = Arc::new(WebSocketManager::new());
        Self { manager }
    }

    /// Get WebSocket manager (clone the Arc).
    pub fn manager(&self) -> Arc<WebSocketManager> {
        Arc::clone(&self.manager)
    }

    /// Handle WebSocket upgrade with optional user authentication
    pub async fn handle_upgrade(
        &self,
        request: Request<Body>,
        user_id: Option<String>,
    ) -> Result<Response<Body>, Box<dyn std::error::Error + Send + Sync>> {
        self.manager.handle_upgrade(request, user_id).await
    }
}

impl crate::plugin::Plugin for WebSocketPlugin {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &'static str {
        "websocket"
    }

    fn init(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}
