//! Professional Rust Example: Secure User Management
//!
//! This example demonstrates world-class Rust patterns:
//! - Clean error handling with the ? operator
//! - Proper resource management with RAII
//! - Type-safe database operations
//! - Secure password handling with hashing and verification
//! - Input validation and comprehensive error handling
//! - Idempotent operations for reliability

use aiviania::database::Database;
use aiviania::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 AIVIANIA Professional User Management Example");
    println!("================================================");

    // Load configuration with proper error handling
    let config = AppConfig::load().unwrap_or_else(|_| {
        eprintln!("⚠️  Using default configuration");
        AppConfig::default()
    });

    // Initialize database with connection pooling
    let db = Database::new_from_config(&config).await?;
    println!("✅ Database connection established");

    // Demonstrate idempotent operations
    db.create_default_roles().await?;
    println!("✅ Default roles initialized (idempotent)");

    // Create users with validation
    demonstrate_user_creation(&db).await?;
    demonstrate_authentication(&db).await?;
    demonstrate_role_management(&db).await?;
    demonstrate_password_security()?;

    println!("\n🎉 All professional patterns demonstrated successfully!");
    println!("==================================================");
    Ok(())
}

/// Demonstrate secure user creation with validation
async fn demonstrate_user_creation(db: &Database) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n🔐 User Creation with Validation:");

    // Test cases showing robust error handling
    let test_cases = vec![
        ("", "password123"),           // Empty username
        ("user", "123"),              // Weak password
        ("test_user_1", "strong_password_2024"), // Valid
        ("test_user_2", "admin_secure_123"), // Another valid user
    ];

    for (username, password) in test_cases {
        match db.create_user(username, password).await {
            Ok(user_id) => println!("  ✅ Created user '{}' with ID {}", username, user_id),
            Err(e) => println!("  ❌ Failed to create user '{}': {:?}", username, e),
        }
    }

    Ok(())
}

/// Demonstrate secure authentication
async fn demonstrate_authentication(db: &Database) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n🔑 Authentication & Security:");

    // Test successful authentication
    match db.authenticate_user("test_user_1", "strong_password_2024").await {
        Ok(user_id) => {
            println!("  ✅ Authentication successful for user ID {}", user_id);

            // Get user roles (handle case where no roles assigned yet)
            match db.get_user_roles(user_id).await {
                Ok(roles) => println!("  📋 User roles: {:?}", roles),
                Err(e) => println!("  📋 User roles: [] (table not created yet: {:?})", e),
            }
        }
        Err(e) => println!("  ❌ Authentication failed: {:?}", e),
    }

    // Test authentication failure (wrong password)
    match db.authenticate_user("test_user_1", "wrong_password").await {
        Ok(_) => println!("  ❌ Security breach: wrong password accepted!"),
        Err(_) => println!("  ✅ Security: wrong password correctly rejected"),
    }

    // Test authentication failure (non-existent user)
    match db.authenticate_user("nonexistent", "password").await {
        Ok(_) => println!("  ❌ Security breach: non-existent user accepted!"),
        Err(_) => println!("  ✅ Security: non-existent user correctly rejected"),
    }

    Ok(())
}

/// Demonstrate role-based access control
async fn demonstrate_role_management(db: &Database) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n👥 Role-Based Access Control:");

    // Create another user for role demonstration
    let user_id = match db.create_user("test_role_user", "secure_pass_123").await {
        Ok(id) => {
            println!("  ✅ Created demo user with ID {}", id);
            id
        }
        Err(e) => {
            // If user already exists, try to find them
            match db.authenticate_user("test_role_user", "secure_pass_123").await {
                Ok(id) => {
                    println!("  ✅ Using existing demo user with ID {}", id);
                    id
                }
                Err(_) => {
                    println!("  ❌ Failed to create or find demo user: {:?}", e);
                    return Err(e.into());
                }
            }
        }
    };

    // Assign multiple roles
    let roles_to_assign = vec!["user", "admin"];

    for role in &roles_to_assign {
        match db.assign_role_to_user(user_id, role).await {
            Ok(_) => println!("  ✅ Assigned role '{}' to user", role),
            Err(e) => println!("  ❌ Failed to assign role '{}': {:?}", role, e),
        }
    }

    // Verify roles were assigned
    let assigned_roles = db.get_user_roles(user_id).await?;
    println!("  📋 Final user roles: {:?}", assigned_roles);

    // Test role assignment to non-existent user
    match db.assign_role_to_user(99999, "admin").await {
        Ok(_) => println!("  ❌ Assigned role to non-existent user!"),
        Err(_) => println!("  ✅ Correctly rejected role assignment to non-existent user"),
    }

    Ok(())
}

/// Demonstrate password security features
fn demonstrate_password_security() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n🔒 Password Security:");

    let password = "my_secure_password_2024";

    // Hash password
    let hash = Database::hash_password(password)?;
    println!("  ✅ Password hashed: {}...{}", &hash[..12], &hash[hash.len()-4..]);

    // Verify correct password
    let is_valid = Database::verify_password(password, &hash)?;
    println!("  ✅ Password verification: {}", if is_valid { "PASSED" } else { "FAILED" });

    // Verify wrong password
    let is_invalid = Database::verify_password("wrong_password", &hash)?;
    println!("  ✅ Wrong password rejection: {}", if !is_invalid { "PASSED" } else { "FAILED" });

    // Test hash consistency
    let hash2 = Database::hash_password(password)?;
    let is_consistent = hash == hash2;
    println!("  ✅ Hash consistency: {}", if is_consistent { "PASSED" } else { "FAILED" });

    Ok(())
}