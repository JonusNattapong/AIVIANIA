use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Email configuration
#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP username
    pub smtp_username: String,
    /// SMTP password
    pub smtp_password: String,
    /// Use TLS encryption
    pub use_tls: bool,
    /// From email address
    pub from_email: String,
    /// From name
    pub from_name: String,
    /// Email templates directory
    pub templates_dir: String,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_username: "".to_string(),
            smtp_password: "".to_string(),
            use_tls: true,
            from_email: "noreply@example.com".to_string(),
            from_name: "AIVIANIA".to_string(),
            templates_dir: "./templates".to_string(),
        }
    }
}

/// Email template data
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailTemplateData {
    /// Recipient name
    pub name: String,
    /// Verification token/code
    pub token: Option<String>,
    /// Reset password URL
    pub reset_url: Option<String>,
    /// Custom data
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Email service for sending emails
pub struct EmailService {
    config: EmailConfig,
    templates: RwLock<Handlebars<'static>>,
    mailer: SmtpTransport,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> Result<Self, EmailError> {
        let creds = Credentials::new(
            config.smtp_username.clone(),
            config.smtp_password.clone(),
        );

        let mailer = if config.use_tls {
            SmtpTransport::relay(&config.smtp_host)
                .map_err(|e| EmailError::SmtpConfig(e.to_string()))?
                .credentials(creds)
                .build()
        } else {
            SmtpTransport::builder_dangerous(&config.smtp_host)
                .credentials(creds)
                .build()
        };

        let mut templates = Handlebars::new();
        templates.set_strict_mode(true);

        // Register default templates
        templates.register_template_string("verification", include_str!("../templates/verification.html"))
            .map_err(|e| EmailError::Template(e.to_string()))?;
        templates.register_template_string("password_reset", include_str!("../templates/password_reset.html"))
            .map_err(|e| EmailError::Template(e.to_string()))?;
        templates.register_template_string("welcome", include_str!("../templates/welcome.html"))
            .map_err(|e| EmailError::Template(e.to_string()))?;

        Ok(Self {
            config,
            templates: RwLock::new(templates),
            mailer,
        })
    }

    /// Send a verification email
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        to_name: &str,
        verification_token: &str,
    ) -> Result<(), EmailError> {
        let data = EmailTemplateData {
            name: to_name.to_string(),
            token: Some(verification_token.to_string()),
            reset_url: None,
            custom: HashMap::new(),
        };

        self.send_template_email(
            to_email,
            &format!("{} - Verify Your Email", self.config.from_name),
            "verification",
            &data,
        ).await
    }

    /// Send a password reset email
    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        to_name: &str,
        reset_token: &str,
    ) -> Result<(), EmailError> {
        let reset_url = format!("{}/reset-password?token={}", "https://yourapp.com", reset_token);

        let data = EmailTemplateData {
            name: to_name.to_string(),
            token: Some(reset_token.to_string()),
            reset_url: Some(reset_url),
            custom: HashMap::new(),
        };

        self.send_template_email(
            to_email,
            &format!("{} - Reset Your Password", self.config.from_name),
            "password_reset",
            &data,
        ).await
    }

    /// Send a welcome email
    pub async fn send_welcome_email(
        &self,
        to_email: &str,
        to_name: &str,
    ) -> Result<(), EmailError> {
        let data = EmailTemplateData {
            name: to_name.to_string(),
            token: None,
            reset_url: None,
            custom: HashMap::new(),
        };

        self.send_template_email(
            to_email,
            &format!("Welcome to {}!", self.config.from_name),
            "welcome",
            &data,
        ).await
    }

    /// Send a custom email using template
    pub async fn send_template_email(
        &self,
        to_email: &str,
        subject: &str,
        template_name: &str,
        data: &EmailTemplateData,
    ) -> Result<(), EmailError> {
        let templates = self.templates.read().await;
        let html_body = templates.render(template_name, data)
            .map_err(|e| EmailError::Template(e.to_string()))?;

        let email = Message::builder()
            .from(format!("{} <{}>", self.config.from_name, self.config.from_email).parse()
                .map_err(|e: lettre::address::AddressError| EmailError::MessageFormat(e.to_string()))?)
            .to(format!("{} <{}>", data.name, to_email).parse()
                .map_err(|e: lettre::address::AddressError| EmailError::MessageFormat(e.to_string()))?)
            .subject(subject)
            .body(html_body)
            .map_err(|e| EmailError::MessageFormat(e.to_string()))?;

        self.mailer.send(&email)
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Send a plain text email
    pub async fn send_plain_email(
        &self,
        to_email: &str,
        to_name: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), EmailError> {
        let email = Message::builder()
            .from(format!("{} <{}>", self.config.from_name, self.config.from_email).parse()
                .map_err(|e: lettre::address::AddressError| EmailError::MessageFormat(e.to_string()))?)
            .to(format!("{} <{}>", to_name, to_email).parse()
                .map_err(|e: lettre::address::AddressError| EmailError::MessageFormat(e.to_string()))?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| EmailError::MessageFormat(e.to_string()))?;

        self.mailer.send(&email)
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Register a custom email template
    pub async fn register_template(&self, name: &str, template: &str) -> Result<(), EmailError> {
        let mut templates = self.templates.write().await;
        templates.register_template_string(name, template)
            .map_err(|e| EmailError::Template(e.to_string()))?;
        Ok(())
    }

    /// Test email connection
    pub fn test_connection(&self) -> Result<(), EmailError> {
        // Try to establish connection
        let _ = self.mailer.test_connection()
            .map_err(|e| EmailError::ConnectionFailed(e.to_string()))?;
        Ok(())
    }
}

/// Email errors
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("SMTP configuration error: {0}")]
    SmtpConfig(String),
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Template error: {0}")]
    Template(String),
    #[error("Message format error: {0}")]
    MessageFormat(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Email verification service
pub struct EmailVerificationService {
    email_service: Arc<EmailService>,
    verification_tokens: RwLock<HashMap<String, VerificationData>>,
}

#[derive(Debug, Clone)]
pub struct VerificationData {
    pub email: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl EmailVerificationService {
    pub fn new(email_service: Arc<EmailService>) -> Self {
        Self {
            email_service,
            verification_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Send verification email and store token
    pub async fn send_verification(&self, email: &str, user_id: &str) -> Result<String, EmailError> {
        let token = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

        let verification_data = VerificationData {
            email: email.to_string(),
            user_id: user_id.to_string(),
            expires_at,
        };

        {
            let mut tokens = self.verification_tokens.write().await;
            tokens.insert(token.clone(), verification_data);
        }

        self.email_service.send_verification_email(email, "User", &token).await?;

        Ok(token)
    }

    /// Verify email token
    pub async fn verify_token(&self, token: &str) -> Result<VerificationData, EmailError> {
        let mut tokens = self.verification_tokens.write().await;
        if let Some(data) = tokens.remove(token) {
            if chrono::Utc::now() < data.expires_at {
                Ok(data)
            } else {
                Err(EmailError::Config("Token expired".to_string()))
            }
        } else {
            Err(EmailError::Config("Invalid token".to_string()))
        }
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired(&self) {
        let mut tokens = self.verification_tokens.write().await;
        let now = chrono::Utc::now();
        tokens.retain(|_, data| data.expires_at > now);
    }
}

/// Password reset service
pub struct PasswordResetService {
    email_service: Arc<EmailService>,
    reset_tokens: RwLock<HashMap<String, ResetData>>,
}

#[derive(Debug, Clone)]
pub struct ResetData {
    pub email: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl PasswordResetService {
    pub fn new(email_service: Arc<EmailService>) -> Self {
        Self {
            email_service,
            reset_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Send password reset email
    pub async fn send_reset_email(&self, email: &str, user_id: &str) -> Result<String, EmailError> {
        let token = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

        let reset_data = ResetData {
            email: email.to_string(),
            user_id: user_id.to_string(),
            expires_at,
        };

        {
            let mut tokens = self.reset_tokens.write().await;
            tokens.insert(token.clone(), reset_data);
        }

        self.email_service.send_password_reset_email(email, "User", &token).await?;

        Ok(token)
    }

    /// Verify reset token
    pub async fn verify_reset_token(&self, token: &str) -> Result<ResetData, EmailError> {
        let mut tokens = self.reset_tokens.write().await;
        if let Some(data) = tokens.remove(token) {
            if chrono::Utc::now() < data.expires_at {
                Ok(data)
            } else {
                Err(EmailError::Config("Reset token expired".to_string()))
            }
        } else {
            Err(EmailError::Config("Invalid reset token".to_string()))
        }
    }

    /// Clean up expired reset tokens
    pub async fn cleanup_expired(&self) {
        let mut tokens = self.reset_tokens.write().await;
        let now = chrono::Utc::now();
        tokens.retain(|_, data| data.expires_at > now);
    }
}