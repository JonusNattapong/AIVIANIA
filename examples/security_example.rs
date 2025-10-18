//! Security Module Example
//!
//! This example demonstrates how to use the AIVIANIA security module
//! to protect your web application with comprehensive security features.

/// Simple security demonstration
pub fn demonstrate_security_features() {
    println!("AIVIANIA Security Module Features:");
    println!("=================================");
    println!("✅ CSRF (Cross-Site Request Forgery) Protection");
    println!("✅ CORS (Cross-Origin Resource Sharing) Handling");
    println!("✅ Security Headers (HSTS, CSP, X-Frame-Options)");
    println!("✅ Input Validation and Sanitization");
    println!("✅ Rate Limiting with Security Rules");
    println!("✅ Security Event Logging and Monitoring");
    println!("✅ Configurable Security Policies");
    println!("✅ Alert System for Security Events");
    println!("");
    println!("Environment Variables for Configuration:");
    println!("- AIVIANIA_CSRF_ENABLED=true");
    println!("- AIVIANIA_CORS_ENABLED=true");
    println!("- AIVIANIA_HEADERS_ENABLED=true");
    println!("- AIVIANIA_VALIDATION_ENABLED=true");
    println!("- AIVIANIA_RATE_LIMIT_ENABLED=true");
    println!("- AIVIANIA_LOG_ENABLED=true");
}

fn main() {
    // Provide a simple runnable example entrypoint so this file can be built as an
    // example. It simply prints the demonstration output.
    demonstrate_security_features();
}
