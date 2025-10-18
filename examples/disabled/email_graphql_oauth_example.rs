use aiviania::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal example: initialize email service if available and run a tiny server
    let config = AppConfig::from_env();

    // If EmailService is available, create a simple instance; otherwise skip
    #[allow(unused_variables)]
    let _email = if cfg!(feature = "email") {
        let ec = EmailConfig {
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "user".to_string(),
            smtp_password: "pass".to_string(),
            use_tls: false,
            from_email: "noreply@example.com".to_string(),
            from_name: "Example".to_string(),
            templates_dir: "./templates".to_string(),
        };
        Some(Arc::new(EmailService::new(ec)?))
    } else {
        None
    };

    println!("Minimal email example - nothing to run interactively.");
    Ok(())
}
use aiviania::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Example demonstrating Email, GraphQL, and OAuth integration
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This example has been moved to examples/disabled because it needs a larger refactor
    // to match the current public API (handlers must be converted to closures that capture
    // service instances or the server needs a state API). Keep this file as a reference.
    println!("This example is disabled for now. See examples/disabled for reference.");
    Ok(())
}
