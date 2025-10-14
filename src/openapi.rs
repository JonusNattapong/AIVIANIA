use serde::Serialize;
use crate::router::Router;
use std::collections::HashMap;

#[cfg(feature = "utoipa")]
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
#[cfg(feature = "utoipa")]
use utoipa::{Modify, OpenApi};
#[cfg(feature = "utoipa")]
use utoipa::openapi::Info;

/// OpenAPI documentation generator
#[cfg(feature = "utoipa")]
#[derive(OpenApi)]
#[openapi(
    paths(),
    components(
        schemas(),
    ),
    modifiers(&SecurityAddon),
    security(
        ("api_key" = [])
    ),
    tags(
        (name = "AIVIANIA", description = "AIVIANIA Web Framework API")
    )
)]
struct ApiDoc;

#[cfg(feature = "utoipa")]
struct SecurityAddon;

#[cfg(feature = "utoipa")]
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("authorization"))),
        );
    }
}

/// OpenAPI documentation service
pub struct OpenApiService {
    #[cfg(feature = "utoipa")]
    openapi: utoipa::openapi::OpenApi,
}

impl OpenApiService {
    /// Create new OpenAPI service
    pub fn new() -> Self {
        #[cfg(feature = "utoipa")]
        let openapi = ApiDoc::openapi();

        Self {
            #[cfg(feature = "utoipa")]
            openapi,
        }
    }

    /// Generate OpenAPI JSON specification
    pub fn generate_openapi_json(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(feature = "utoipa")]
        {
            let json = self.openapi.to_json()?;
            Ok(json)
        }

        #[cfg(not(feature = "utoipa"))]
        {
            Ok(self.generate_basic_openapi())
        }
    }

    /// Generate basic OpenAPI document when utoipa is not available
    fn generate_basic_openapi(&self) -> String {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {
                "title": "AIVIANIA API",
                "version": "0.1.3",
                "description": "AIVIANIA Web Framework API Documentation"
            },
            "servers": [
                {
                    "url": "http://localhost:3000",
                    "description": "Development server"
                }
            ],
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check endpoint",
                        "responses": {
                            "200": {
                                "description": "Server is healthy",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "status": {"type": "string"},
                                                "timestamp": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/graphql": {
                    "get": {
                        "summary": "GraphQL playground",
                        "responses": {
                            "200": {
                                "description": "GraphQL playground interface"
                            }
                        }
                    },
                    "post": {
                        "summary": "Execute GraphQL query",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "query": {"type": "string"},
                                            "variables": {"type": "object"},
                                            "operationName": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "GraphQL response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "data": {"type": "object"},
                                                "errors": {
                                                    "type": "array",
                                                    "items": {"type": "object"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/ws": {
                    "get": {
                        "summary": "WebSocket connection endpoint",
                        "description": "Establish WebSocket connection for real-time communication",
                        "responses": {
                            "101": {
                                "description": "WebSocket connection established"
                            }
                        }
                    }
                },
                "/upload": {
                    "post": {
                        "summary": "File upload endpoint",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": {
                                                "type": "string",
                                                "format": "binary"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "File uploaded successfully",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "filename": {"type": "string"},
                                                "size": {"type": "integer"},
                                                "url": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKey": {
                        "type": "apiKey",
                        "name": "authorization",
                        "in": "header"
                    }
                }
            },
            "security": [
                {
                    "bearerAuth": []
                }
            ]
        }).to_string()
    }

    /// Serve OpenAPI JSON specification
    pub fn serve_openapi_json(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.generate_openapi_json()
    }

    /// Serve Swagger UI HTML
    #[cfg(feature = "utoipa")]
    pub fn serve_swagger_ui(&self) -> String {
        utoipa_swagger_ui::SwaggerUi::new("/swagger-ui/{_:.*}")
            .url("/api-docs/openapi.json", &self.openapi)
            .to_html()
    }

    /// Serve Swagger UI HTML (basic version)
    #[cfg(not(feature = "utoipa"))]
    pub fn serve_swagger_ui(&self) -> String {
        format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>AIVIANIA API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui.css" />
    <style>
        html {{
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }}
        *, *:before, *:after {{
            box-sizing: inherit;
        }}
        body {{
            margin:0;
            background: #fafafa;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.7.2/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '/api-docs/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            }});
        }};
    </script>
</body>
</html>
"#)
    }
}

/// Generate OpenAPI documentation from router (legacy method)
pub async fn serve_openapi(_router: &Router) -> Result<String, ()> {
    let service = OpenApiService::new();
    service.serve_openapi_json().map_err(|_| ())
}
