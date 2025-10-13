use thiserror::Error;
use hyper::StatusCode;

#[derive(Error, Debug)]
pub enum AivianiaError {
    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden")]
    Forbidden,
}

impl AivianiaError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AivianiaError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AivianiaError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AivianiaError::Unauthorized => StatusCode::UNAUTHORIZED,
            AivianiaError::Forbidden => StatusCode::FORBIDDEN,
        }
    }
}
