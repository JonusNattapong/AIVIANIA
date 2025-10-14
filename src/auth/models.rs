//! User and role models for authentication.
//!
//! This module defines the core data structures for users, roles,
//! and authentication-related entities.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// User roles for role-based access control
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Super administrator with all permissions
    Admin,
    /// Regular user with basic permissions
    User,
    /// Moderator with elevated permissions
    Moderator,
    /// Guest user with limited access
    Guest,
    /// Custom role for specific use cases
    Custom(String),
}

/// User permissions for fine-grained access control
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // User management
    CreateUser,
    ReadUser,
    UpdateUser,
    DeleteUser,

    // Content management
    CreateContent,
    ReadContent,
    UpdateContent,
    DeleteContent,

    // System administration
    ManageUsers,
    ManageRoles,
    ViewAnalytics,
    SystemConfig,

    // API access
    ApiAccess,
    WebSocketAccess,

    // Custom permissions
    Custom(String),
}

/// User model representing an authenticated user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub roles: HashSet<Role>,
    pub permissions: HashSet<Permission>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

/// User role assignment for RBAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    pub user_id: String,
    pub role: Role,
    pub assigned_at: chrono::DateTime<chrono::Utc>,
    pub assigned_by: String,
}

/// Login credentials
#[derive(Debug, Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

/// Registration data
#[derive(Debug, Deserialize)]
pub struct RegistrationData {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Password change request
#[derive(Debug, Deserialize)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Token response for login
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
}

/// User information for token response
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl User {
    /// Create a new user
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            username,
            email,
            password_hash,
            roles: HashSet::new(),
            permissions: HashSet::new(),
            is_active: true,
            created_at: now,
            updated_at: now,
            last_login: None,
        }
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }

    /// Check if user has a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        // Check direct permissions
        if self.permissions.contains(permission) {
            return true;
        }

        // Check role-based permissions
        for role in &self.roles {
            match role {
                Role::Admin => return true, // Admin has all permissions
                Role::Moderator => match permission {
                    Permission::CreateContent
                    | Permission::ReadContent
                    | Permission::UpdateContent
                    | Permission::ApiAccess
                    | Permission::WebSocketAccess => return true,
                    _ => {}
                },
                Role::User => match permission {
                    Permission::ReadContent
                    | Permission::ApiAccess
                    | Permission::WebSocketAccess => return true,
                    _ => {}
                },
                Role::Guest => match permission {
                    Permission::ReadContent => return true,
                    _ => {}
                },
                Role::Custom(_) => {} // Custom roles need explicit permissions
            }
        }

        false
    }

    /// Add a role to the user
    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role);
        self.updated_at = chrono::Utc::now();
    }

    /// Remove a role from the user
    pub fn remove_role(&mut self, role: &Role) {
        self.roles.remove(role);
        self.updated_at = chrono::Utc::now();
    }

    /// Add a permission to the user
    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission);
        self.updated_at = chrono::Utc::now();
    }

    /// Remove a permission from the user
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
        self.updated_at = chrono::Utc::now();
    }

    /// Update last login time
    pub fn update_last_login(&mut self) {
        self.last_login = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    /// Convert to UserInfo for API responses
    pub fn to_user_info(&self) -> UserInfo {
        UserInfo {
            id: self.id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            roles: self.roles.iter().map(|r| format!("{:?}", r)).collect(),
            permissions: self.permissions.iter().map(|p| format!("{:?}", p)).collect(),
        }
    }
}

impl From<&User> for UserInfo {
    fn from(user: &User) -> Self {
        user.to_user_info()
    }
}