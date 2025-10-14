//! Database Integration Example
//!
//! This example demonstrates how to use the AIVIANIA database integration
//! with SQLite backend, including repository pattern and RBAC.

use aiviania::database::{DatabaseConfig, DatabaseManager, DatabaseType, Repository};
use aiviania::database::repositories::UserRepository;
use aiviania::auth::rbac::RBACService;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 AIVIANIA Database Integration Example");
    println!("========================================");

    // 1. Configure SQLite database
    let config = DatabaseConfig {
        database_type: DatabaseType::Sqlite,
        connection_string: ":memory:".to_string(), // In-memory database
        max_connections: 5,
        min_connections: 1,
        connection_timeout: 30,
        acquire_timeout: 10,
        idle_timeout: 300,
        max_lifetime: 3600,
    };

    println!("📊 Creating database connection...");
    let db_manager = DatabaseManager::new(config).await?;
    println!("✅ Database connected successfully!");

    // 1.5. Set up database schema manually for this example
    println!("\n🛠️  Setting up database schema...");
    let create_table_query = r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            first_name VARCHAR(255),
            last_name VARCHAR(255),
            avatar_url VARCHAR(500),
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    "#;
    db_manager.connection().execute(create_table_query, vec![]).await?;
    println!("✅ Database schema created!");

    // 2. Create repository
    println!("\n👤 Creating user repository...");
    let user_repo = UserRepository::new(db_manager);
    println!("✅ Repository created!");

    // 3. Create RBAC service
    println!("\n🔐 Setting up RBAC service...");
    let rbac_service = Arc::new(RBACService::new());
    println!("✅ RBAC service ready!");

    // 4. Create a test user
    println!("\n👤 Creating a test user...");
    use aiviania::database::repositories::User;
    use chrono::Utc;

    let test_user = User {
        id: None, // Will be auto-generated
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "hashed_password_here".to_string(),
        role: "user".to_string(),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        avatar_url: None,
        is_active: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Save the user
    let user_id = user_repo.save(test_user).await?;
    println!("✅ User created with ID: {:?}", user_id);

    // 5. Retrieve the user
    println!("\n🔍 Retrieving user by ID...");
    let retrieved_user = user_repo.find_by_id(user_id).await?;
    match retrieved_user {
        Some(user) => {
            println!("✅ User found:");
            println!("   Username: {}", user.username);
            println!("   Email: {}", user.email);
            println!("   Role: {}", user.role);
            println!("   Active: {}", user.is_active);

            // 6. Test RBAC
            println!("\n🔐 Testing RBAC...");
            let auth_user = user.to_auth_user();
            let has_user_role = rbac_service.has_role(&auth_user, &aiviania::auth::models::Role::User);
            println!("   User has 'User' role: {}", has_user_role);
        }
        None => println!("❌ User not found"),
    }

    // 7. List all users
    println!("\n📋 Listing all users...");
    let all_users = user_repo.find_all().await?;
    println!("✅ Found {} user(s)", all_users.len());

    // 8. Update the user
    println!("\n✏️  Updating user...");
    if let Some(mut user) = user_repo.find_by_id(user_id).await? {
        user.first_name = Some("Updated".to_string());
        user.last_name = Some("Name".to_string());
        user.updated_at = Utc::now();

        user_repo.update(user.clone()).await?;
        println!("✅ User updated successfully!");
        println!("   New name: {} {}", user.first_name.unwrap_or_default(), user.last_name.unwrap_or_default());
    }

    // 9. Clean up - delete the user
    println!("\n🗑️  Deleting user...");
    user_repo.delete_by_id(user_id).await?;
    println!("✅ User deleted successfully!");

    // 10. Verify deletion
    println!("\n🔍 Verifying deletion...");
    let deleted_user = user_repo.find_by_id(user_id).await?;
    match deleted_user {
        Some(_) => println!("❌ User still exists"),
        None => println!("✅ User successfully deleted"),
    }

    println!("\n🎉 Database integration example completed successfully!");
    println!("==================================================");
    println!("Features demonstrated:");
    println!("  ✅ Multi-backend database support (SQLite)");
    println!("  ✅ Repository pattern implementation");
    println!("  ✅ CRUD operations (Create, Read, Update, Delete)");
    println!("  ✅ RBAC integration");
    println!("  ✅ Async/await support");
    println!("  ✅ Error handling");

    Ok(())
}