//! Security Events and Logging

use super::*;
use std::collections::HashMap;

/// Security event logger (already defined in mod.rs, this file contains additional utilities)

/// Security event filter
pub struct EventFilter {
    pub event_types: Vec<String>,
    pub severities: Vec<SecuritySeverity>,
    pub ip_addresses: Vec<String>,
    pub time_range: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl EventFilter {
    /// Create a new event filter
    pub fn new() -> Self {
        Self {
            event_types: Vec::new(),
            severities: Vec::new(),
            ip_addresses: Vec::new(),
            time_range: None,
        }
    }

    /// Filter events by type
    pub fn by_event_type(mut self, event_type: String) -> Self {
        self.event_types.push(event_type);
        self
    }

    /// Filter events by severity
    pub fn by_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severities.push(severity);
        self
    }

    /// Filter events by IP address
    pub fn by_ip(mut self, ip: String) -> Self {
        self.ip_addresses.push(ip);
        self
    }

    /// Filter events by time range
    pub fn by_time_range(mut self, start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> Self {
        self.time_range = Some((start, end));
        self
    }

    /// Apply filter to events
    pub fn apply<'a>(&self, events: &'a [SecurityEvent]) -> Vec<&'a SecurityEvent> {
        events.iter().filter(|event| {
            // Check event type
            if !self.event_types.is_empty() {
                let event_type = match event {
                    SecurityEvent::CsrfAttackAttempt { .. } => "csrf",
                    SecurityEvent::CorsViolation { .. } => "cors",
                    SecurityEvent::InputValidationFailure { .. } => "validation",
                    SecurityEvent::RateLimitExceeded { .. } => "rate_limit",
                    SecurityEvent::SuspiciousActivity { .. } => "suspicious",
                };
                if !self.event_types.contains(&event_type.to_string()) {
                    return false;
                }
            }

            // Check severity
            if !self.severities.is_empty() {
                let severity = match event {
                    SecurityEvent::CsrfAttackAttempt { .. } => SecuritySeverity::High,
                    SecurityEvent::CorsViolation { .. } => SecuritySeverity::Medium,
                    SecurityEvent::InputValidationFailure { .. } => SecuritySeverity::Low,
                    SecurityEvent::RateLimitExceeded { .. } => SecuritySeverity::Medium,
                    SecurityEvent::SuspiciousActivity { severity, .. } => severity.clone(),
                };
                if !self.severities.contains(&severity) {
                    return false;
                }
            }

            // Check IP address
            if !self.ip_addresses.is_empty() {
                let ip = match event {
                    SecurityEvent::CsrfAttackAttempt { ip, .. } => ip,
                    SecurityEvent::RateLimitExceeded { ip, .. } => ip,
                    SecurityEvent::SuspiciousActivity { ip, .. } => ip,
                    _ => "unknown",
                };
                if !self.ip_addresses.contains(&ip.to_string()) {
                    return false;
                }
            }

            // Check time range
            if let Some((start, end)) = self.time_range {
                let event_time = match event {
                    SecurityEvent::CsrfAttackAttempt { timestamp, .. } => *timestamp,
                    SecurityEvent::CorsViolation { timestamp, .. } => *timestamp,
                    SecurityEvent::InputValidationFailure { timestamp, .. } => *timestamp,
                    SecurityEvent::RateLimitExceeded { timestamp, .. } => *timestamp,
                    SecurityEvent::SuspiciousActivity { timestamp, .. } => *timestamp,
                };
                if event_time < start || event_time > end {
                    return false;
                }
            }

            true
        }).collect()
    }
}

/// Security event exporter
pub struct EventExporter;

impl EventExporter {
    /// Export events to JSON
    pub fn to_json(events: &[SecurityEvent]) -> serde_json::Value {
        serde_json::json!({
            "events": events,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "total_count": events.len()
        })
    }

    /// Export events to CSV
    pub fn to_csv(events: &[SecurityEvent]) -> String {
        let mut csv = String::from("timestamp,event_type,severity,details\n");

        for event in events {
            // normalize into (timestamp, event_type, severity, details) all as owned values
            let (ts, event_type, severity, details) = match event {
                SecurityEvent::CsrfAttackAttempt { timestamp, ip, url, .. } => {
                    (timestamp.clone(), "csrf_attack".to_string(), "high".to_string(), format!("ip={}, url={}", ip, url))
                }
                SecurityEvent::CorsViolation { timestamp, origin, method, .. } => {
                    (timestamp.clone(), "cors_violation".to_string(), "medium".to_string(), format!("origin={:?}, method={}", origin, method))
                }
                SecurityEvent::InputValidationFailure { timestamp, field, rule, .. } => {
                    (timestamp.clone(), "validation_failure".to_string(), "low".to_string(), format!("field={}, rule={}", field, rule))
                }
                SecurityEvent::RateLimitExceeded { timestamp, ip, endpoint, limit, .. } => {
                    (timestamp.clone(), "rate_limit_exceeded".to_string(), "medium".to_string(), format!("ip={}, endpoint={}, limit={}", ip, endpoint, limit))
                }
                SecurityEvent::SuspiciousActivity { timestamp, ip, activity, severity, .. } => {
                    (timestamp.clone(), "suspicious_activity".to_string(), format!("{:?}", severity).to_lowercase(), format!("ip={}, activity={}", ip, activity))
                }
            };

            csv.push_str(&format!("{},{},{},{}\n", ts.to_rfc3339(), event_type, severity, details));
        }

        csv
    }
}

/// Security metrics calculator
pub struct SecurityMetricsCalculator;

impl SecurityMetricsCalculator {
    /// Calculate security metrics from events
    pub fn calculate(events: &[SecurityEvent]) -> SecurityMetrics {
        let mut metrics = SecurityMetrics {
            total_events: events.len(),
            csrf_attempts: 0,
            cors_violations: 0,
            validation_failures: 0,
            rate_limit_exceeded: 0,
            suspicious_activities: 0,
            events_by_hour: HashMap::new(),
            top_attack_sources: HashMap::new(),
        };

        for event in events {
            match event {
                SecurityEvent::CsrfAttackAttempt { timestamp, ip, .. } => {
                    metrics.csrf_attempts += 1;
                    *metrics.top_attack_sources.entry(ip.clone()).or_insert(0) += 1;
                    Self::increment_hourly(&mut metrics.events_by_hour, *timestamp);
                }
                SecurityEvent::CorsViolation { timestamp, .. } => {
                    metrics.cors_violations += 1;
                    Self::increment_hourly(&mut metrics.events_by_hour, *timestamp);
                }
                SecurityEvent::InputValidationFailure { timestamp, .. } => {
                    metrics.validation_failures += 1;
                    Self::increment_hourly(&mut metrics.events_by_hour, *timestamp);
                }
                SecurityEvent::RateLimitExceeded { timestamp, ip, .. } => {
                    metrics.rate_limit_exceeded += 1;
                    *metrics.top_attack_sources.entry(ip.clone()).or_insert(0) += 1;
                    Self::increment_hourly(&mut metrics.events_by_hour, *timestamp);
                }
                SecurityEvent::SuspiciousActivity { timestamp, ip, severity, .. } => {
                    metrics.suspicious_activities += 1;
                    if *severity == SecuritySeverity::High || *severity == SecuritySeverity::Critical {
                        *metrics.top_attack_sources.entry(ip.clone()).or_insert(0) += 1;
                    }
                    Self::increment_hourly(&mut metrics.events_by_hour, *timestamp);
                }
            }
        }

        metrics
    }

    /// Increment hourly counter
    fn increment_hourly(hourly: &mut HashMap<String, u64>, timestamp: chrono::DateTime<chrono::Utc>) {
        let hour = timestamp.format("%Y-%m-%d %H:00").to_string();
        *hourly.entry(hour).or_insert(0) += 1;
    }
}

/// Security metrics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityMetrics {
    pub total_events: usize,
    pub csrf_attempts: u64,
    pub cors_violations: u64,
    pub validation_failures: u64,
    pub rate_limit_exceeded: u64,
    pub suspicious_activities: u64,
    pub events_by_hour: HashMap<String, u64>,
    pub top_attack_sources: HashMap<String, u64>,
}

/// Security alert system
pub struct SecurityAlertSystem {
    rules: Vec<AlertRule>,
    alert_cooldown: std::time::Duration,
    last_alerts: HashMap<String, chrono::DateTime<chrono::Utc>>,
}

impl SecurityAlertSystem {
    /// Create a new alert system
    pub fn new(alert_cooldown: std::time::Duration) -> Self {
        Self {
            rules: Vec::new(),
            alert_cooldown,
            last_alerts: HashMap::new(),
        }
    }

    /// Add an alert rule
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Check for alerts
    pub async fn check_alerts(&mut self, events: &[SecurityEvent]) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let now = chrono::Utc::now();

        for rule in &self.rules {
            // Check cooldown
            if let Some(last_alert) = self.last_alerts.get(&rule.name) {
                if now.signed_duration_since(*last_alert) < chrono::Duration::seconds(self.alert_cooldown.as_secs() as i64) {
                    continue;
                }
            }

            // Check rule condition
            if rule.check_condition(events) {
                alerts.push(SecurityAlert {
                    rule_name: rule.name.clone(),
                    message: rule.message.clone(),
                    severity: rule.severity.clone(),
                    timestamp: now,
                    triggered_events: rule.get_matching_events(events),
                });

                self.last_alerts.insert(rule.name.clone(), now);
            }
        }

        alerts
    }
}

/// Alert rule
pub struct AlertRule {
    pub name: String,
    pub message: String,
    pub severity: SecuritySeverity,
    pub condition: Box<dyn Fn(&[SecurityEvent]) -> bool + Send + Sync>,
    pub event_filter: Box<dyn Fn(&SecurityEvent) -> bool + Send + Sync>,
}

impl AlertRule {
    /// Create a new alert rule
    pub fn new<F, G>(
        name: String,
        message: String,
        severity: SecuritySeverity,
        condition: F,
        event_filter: G,
    ) -> Self
    where
        F: Fn(&[SecurityEvent]) -> bool + Send + Sync + 'static,
        G: Fn(&SecurityEvent) -> bool + Send + Sync + 'static,
    {
        Self {
            name,
            message,
            severity,
            condition: Box::new(condition),
            event_filter: Box::new(event_filter),
        }
    }

    /// Check if condition is met
    fn check_condition(&self, events: &[SecurityEvent]) -> bool {
        (self.condition)(events)
    }

    /// Get matching events
    fn get_matching_events(&self, events: &[SecurityEvent]) -> Vec<SecurityEvent> {
        events.iter()
            .filter(|event| (self.event_filter)(event))
            .cloned()
            .collect()
    }
}

/// Security alert
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityAlert {
    pub rule_name: String,
    pub message: String,
    pub severity: SecuritySeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub triggered_events: Vec<SecurityEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_csv_contains_headers_and_rows() {
        let now = chrono::Utc::now();
        let events = vec![
            SecurityEvent::CsrfAttackAttempt { ip: "1.2.3.4".to_string(), user_agent: None, url: "/test".to_string(), timestamp: now },
        ];

        let csv = EventExporter::to_csv(&events);
        assert!(csv.contains("timestamp,event_type,severity,details"));
        assert!(csv.contains("csrf_attack"));
        assert!(csv.contains("1.2.3.4"));
    }
}