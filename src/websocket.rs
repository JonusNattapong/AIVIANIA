//! WebSocket module - Real-time communication support.
//!
//! This module provides WebSocket server functionality for real-time bidirectional
//! communication between clients and the server. It implements a simple subprotocol
//! negotiation (selects the first supported protocol requested by the client)
//! and a basic extensions negotiation for `permessage-deflate` (advertised if
//! the client asked for it and we "support" it here).

use base64::{engine::general_purpose, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hyper::{Body, Request, Response, StatusCode};
use hyper::header::{CONNECTION, UPGRADE};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_tungstenite::WebSocketStream;

/// Internal connection handler — spawned per websocket connection.
async fn handle_ws_connection_inner(
    ws_stream: WebSocketStream<hyper::upgrade::Upgraded>,
    connections: Arc<Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<String>>>>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let conn_id = format!("{:p}", &tx); // Simple ID based on pointer

    // Add to connections
    {
        let mut conns = connections.lock().unwrap();
        conns.insert(conn_id.clone(), tx);
    }

    let (mut write, mut read) = ws_stream.split();

    // Task to send messages
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write.send(tokio_tungstenite::tungstenite::Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Task to receive messages
    let connections_clone = connections.clone();
    let conn_id_clone = conn_id.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                    println!("Received: {}", text);
                    // Echo back for now
                    if let Some(tx) = connections_clone.lock().unwrap().get(&conn_id_clone) {
                        let _ = tx.send(format!("Echo: {}", text));
                    }
                }
                Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // Remove from connections
    connections.lock().unwrap().remove(&conn_id);
}

/// WebSocket connection handler.
pub struct WebSocketHandler {
    connections: Arc<Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<String>>>>,
    supported_subprotocols: Vec<String>,
    support_permessage_deflate: bool,
}

impl WebSocketHandler {
    /// Create a new WebSocket handler.
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            supported_subprotocols: vec!["chat".to_string(), "json".to_string()],
            support_permessage_deflate: true,
        }
    }

    /// Handle WebSocket upgrade request with subprotocol and extension negotiation.
    pub async fn handle_upgrade(
        &self,
        mut request: Request<Body>,
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
            let connections = self.connections.clone();
            let chosen_proto = chosen_subprotocol.clone();
            tokio::spawn(async move {
                match on_upgrade.await {
                    Ok(upgraded) => {
                        if let Some(p) = chosen_proto {
                            println!("Negotiated subprotocol: {}", p);
                        }

                        let ws_stream = WebSocketStream::from_raw_socket(
                            upgraded,
                            tokio_tungstenite::tungstenite::protocol::Role::Server,
                            None,
                        ).await;

                        handle_ws_connection_inner(ws_stream, connections).await;
                    }
                    Err(e) => eprintln!("Upgrade error: {:?}", e),
                }
            });
        }

        Ok(response)
    }

    /// Calculate WebSocket accept key.
    fn calculate_accept_key(&self, key: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(key);
        hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let result = hasher.finalize();
        general_purpose::STANDARD.encode(&result)
    }

    /// Broadcast a message to all connections.
    pub fn broadcast(&self, message: &str) {
        let conns = self.connections.lock().unwrap();
        for tx in conns.values() {
            let _ = tx.send(message.to_string());
        }
    }
}


/// WebSocket plugin for the plugin system.
pub struct WebSocketPlugin {
    handler: Arc<WebSocketHandler>,
}

impl WebSocketPlugin {
    /// Create a new WebSocket plugin.
    pub fn new() -> Self {
        let handler = Arc::new(WebSocketHandler::new());
        Self { handler }
    }

    /// Get WebSocket handler (clone the Arc).
    pub fn handler(&self) -> Arc<WebSocketHandler> {
        self.handler.clone()
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
