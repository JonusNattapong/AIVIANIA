//! Role-Based Access Control (RBAC) implementation.
//!
//! This module provides role-based access control functionality
//! for managing user permissions and roles.

use crate::auth::models::{Permission, Role, User};
use std::collections::HashMap;

/// Role-based access control service
pub struct RBACService {
    /// Role-permission mappings
    role_permissions: HashMap<Role, Vec<Permission>>,
    /// Custom role definitions
    custom_roles: HashMap<String, Vec<Permission>>,
}

impl RBACService {
    /// Create a new RBAC service with default role mappings
    pub fn new() -> Self {
        let mut role_permissions = HashMap::new();

        // Define default role permissions
        role_permissions.insert(
            Role::Admin,
            vec![
                Permission::CreateUser,
                Permission::ReadUser,
                Permission::UpdateUser,
                Permission::DeleteUser,
                Permission::CreateContent,
                Permission::ReadContent,
                Permission::UpdateContent,
                Permission::DeleteContent,
                Permission::ManageUsers,
                Permission::ManageRoles,
                Permission::ViewAnalytics,
                Permission::SystemConfig,
                Permission::ApiAccess,
                Permission::WebSocketAccess,
            ],
        );

        role_permissions.insert(
            Role::Moderator,
            vec![
                Permission::CreateContent,
                Permission::ReadContent,
                Permission::UpdateContent,
                Permission::DeleteContent,
                Permission::ApiAccess,
                Permission::WebSocketAccess,
            ],
        );

        role_permissions.insert(
            Role::User,
            vec![
                Permission::ReadContent,
                Permission::CreateContent,
                Permission::UpdateContent,
                Permission::ApiAccess,
                Permission::WebSocketAccess,
            ],
        );

        role_permissions.insert(Role::Guest, vec![Permission::ReadContent]);

        Self {
            role_permissions,
            custom_roles: HashMap::new(),
        }
    }

    /// Check if a user has permission to perform an action
    pub fn has_permission(&self, user: &User, permission: &Permission) -> bool {
        // Check direct user permissions first
        if user.permissions.contains(permission) {
            return true;
        }

        // Check role-based permissions
        for role in &user.roles {
            match role {
                Role::Admin => return true, // Admin has all permissions
                Role::Custom(role_name) => {
                    if let Some(permissions) = self.custom_roles.get(role_name) {
                        if permissions.contains(permission) {
                            return true;
                        }
                    }
                }
                _ => {
                    if let Some(permissions) = self.role_permissions.get(role) {
                        if permissions.contains(permission) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a user has a specific role
    pub fn has_role(&self, user: &User, role: &Role) -> bool {
        user.roles.contains(role)
    }

    /// Get all permissions for a role
    pub fn get_role_permissions(&self, role: &Role) -> Vec<Permission> {
        match role {
            Role::Custom(role_name) => self
                .custom_roles
                .get(role_name)
                .cloned()
                .unwrap_or_default(),
            _ => self.role_permissions.get(role).cloned().unwrap_or_default(),
        }
    }

    /// Get all permissions for a user (combining roles and direct permissions)
    pub fn get_user_permissions(&self, user: &User) -> Vec<Permission> {
        let mut permissions = user.permissions.clone();

        for role in &user.roles {
            let role_permissions = self.get_role_permissions(role);
            permissions.extend(role_permissions);
        }

        // Remove duplicates
        permissions
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Add a custom role with specific permissions
    pub fn add_custom_role(&mut self, role_name: String, permissions: Vec<Permission>) {
        self.custom_roles.insert(role_name, permissions);
    }

    /// Remove a custom role
    pub fn remove_custom_role(&mut self, role_name: &str) {
        self.custom_roles.remove(role_name);
    }

    /// Update permissions for a custom role
    pub fn update_custom_role(&mut self, role_name: String, permissions: Vec<Permission>) {
        self.custom_roles.insert(role_name, permissions);
    }

    /// Add permission to a role
    pub fn add_permission_to_role(&mut self, role: Role, permission: Permission) {
        match role {
            Role::Custom(role_name) => {
                let permissions = self.custom_roles.entry(role_name).or_insert_with(Vec::new);
                if !permissions.contains(&permission) {
                    permissions.push(permission);
                }
            }
            _ => {
                let permissions = self.role_permissions.entry(role).or_insert_with(Vec::new);
                if !permissions.contains(&permission) {
                    permissions.push(permission);
                }
            }
        }
    }

    /// Remove permission from a role
    pub fn remove_permission_from_role(&mut self, role: &Role, permission: &Permission) {
        match role {
            Role::Custom(role_name) => {
                if let Some(permissions) = self.custom_roles.get_mut(role_name) {
                    permissions.retain(|p| p != permission);
                }
            }
            _ => {
                if let Some(permissions) = self.role_permissions.get_mut(role) {
                    permissions.retain(|p| p != permission);
                }
            }
        }
    }

    /// Get all available roles
    pub fn get_available_roles(&self) -> Vec<Role> {
        let mut roles = vec![Role::Admin, Role::Moderator, Role::User, Role::Guest];
        for role_name in self.custom_roles.keys() {
            roles.push(Role::Custom(role_name.clone()));
        }
        roles
    }

    /// Validate if a permission exists
    pub fn is_valid_permission(&self, permission: &Permission) -> bool {
        matches!(
            permission,
            Permission::CreateUser
                | Permission::ReadUser
                | Permission::UpdateUser
                | Permission::DeleteUser
                | Permission::CreateContent
                | Permission::ReadContent
                | Permission::UpdateContent
                | Permission::DeleteContent
                | Permission::ManageUsers
                | Permission::ManageRoles
                | Permission::ViewAnalytics
                | Permission::SystemConfig
                | Permission::ApiAccess
                | Permission::WebSocketAccess
                | Permission::Custom(_)
        )
    }
}

impl Default for RBACService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::models::User;

    #[test]
    fn test_admin_has_all_permissions() {
        let rbac = RBACService::new();
        let mut user = User::new(
            "admin".to_string(),
            "admin@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::Admin);

        assert!(rbac.has_permission(&user, &Permission::CreateUser));
        assert!(rbac.has_permission(&user, &Permission::SystemConfig));
        assert!(rbac.has_permission(&user, &Permission::ViewAnalytics));
    }

    #[test]
    fn test_user_permissions() {
        let rbac = RBACService::new();
        let mut user = User::new(
            "user".to_string(),
            "user@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::User);

        assert!(rbac.has_permission(&user, &Permission::ReadContent));
        assert!(rbac.has_permission(&user, &Permission::ApiAccess));
        assert!(!rbac.has_permission(&user, &Permission::CreateUser));
        assert!(!rbac.has_permission(&user, &Permission::SystemConfig));
    }

    #[test]
    fn test_guest_permissions() {
        let rbac = RBACService::new();
        let mut user = User::new(
            "guest".to_string(),
            "guest@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::Guest);

        assert!(rbac.has_permission(&user, &Permission::ReadContent));
        assert!(!rbac.has_permission(&user, &Permission::CreateContent));
        assert!(!rbac.has_permission(&user, &Permission::ApiAccess));
    }

    #[test]
    fn test_direct_user_permissions() {
        let rbac = RBACService::new();
        let mut user = User::new(
            "user".to_string(),
            "user@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::Guest); // Guest has limited permissions
        user.add_permission(Permission::CreateContent); // But direct permission allows this

        assert!(rbac.has_permission(&user, &Permission::ReadContent)); // From role
        assert!(rbac.has_permission(&user, &Permission::CreateContent)); // From direct permission
        assert!(!rbac.has_permission(&user, &Permission::ApiAccess)); // Not granted
    }

    #[test]
    fn test_custom_role() {
        let mut rbac = RBACService::new();
        rbac.add_custom_role(
            "editor".to_string(),
            vec![
                Permission::CreateContent,
                Permission::ReadContent,
                Permission::UpdateContent,
            ],
        );

        let mut user = User::new(
            "editor".to_string(),
            "editor@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::Custom("editor".to_string()));

        assert!(rbac.has_permission(&user, &Permission::CreateContent));
        assert!(rbac.has_permission(&user, &Permission::ReadContent));
        assert!(rbac.has_permission(&user, &Permission::UpdateContent));
        assert!(!rbac.has_permission(&user, &Permission::DeleteContent));
    }

    #[test]
    fn test_get_user_permissions() {
        let mut rbac = RBACService::new();
        let mut user = User::new(
            "user".to_string(),
            "user@example.com".to_string(),
            "hash".to_string(),
        );
        user.add_role(Role::User);
        user.add_permission(Permission::ViewAnalytics); // Direct permission

        let permissions = rbac.get_user_permissions(&user);

        // Should include User role permissions plus direct permission
        assert!(permissions.contains(&Permission::ReadContent));
        assert!(permissions.contains(&Permission::ApiAccess));
        assert!(permissions.contains(&Permission::ViewAnalytics));
        assert!(!permissions.contains(&Permission::CreateUser)); // Not in User role
    }
}
