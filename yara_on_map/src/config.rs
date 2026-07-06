use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineCfg {
    pub r#type: String,
    pub yara_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCfg {
    pub page_bytes: usize,
    pub timeout_ms: u64,
    pub proc_budget_ms: u64,
    pub cache_ttl_ms: u64,
    pub max_workers: usize,
    pub priorities: Priorities,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Priorities {
    pub exec: u8,
    pub write: u8,
    pub read: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCfg {
    pub listen: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCfg {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCfg {
    pub engine: EngineCfg,
    pub scan: ScanCfg,
    pub mode: String, // audit|enforce
    pub metrics: MetricsCfg,
    pub logging: LogCfg,
}

impl AppCfg {
    pub fn validate(&self) -> Result<()> {
        let engine_type = self.engine.r#type.trim();
        if !engine_type.eq_ignore_ascii_case("external") {
            bail!(
                "engine.type must be `external`, got `{}`",
                self.engine.r#type
            );
        }
        if self.engine.yara_path.trim().is_empty() {
            bail!("engine.yara_path must not be empty");
        }

        if self.scan.page_bytes == 0 {
            bail!("scan.page_bytes must be greater than 0");
        }
        if self.scan.timeout_ms == 0 {
            bail!("scan.timeout_ms must be greater than 0");
        }
        if self.scan.proc_budget_ms == 0 {
            bail!("scan.proc_budget_ms must be greater than 0");
        }
        if self.scan.cache_ttl_ms == 0 {
            bail!("scan.cache_ttl_ms must be greater than 0");
        }
        if self.scan.max_workers == 0 {
            bail!("scan.max_workers must be greater than 0");
        }

        validate_priority("scan.priorities.exec", self.scan.priorities.exec)?;
        validate_priority("scan.priorities.write", self.scan.priorities.write)?;
        validate_priority("scan.priorities.read", self.scan.priorities.read)?;

        let mode = self.mode.trim();
        if !matches!(mode, "audit" | "enforce") {
            bail!("mode must be `audit` or `enforce`, got `{}`", self.mode);
        }

        self.metrics
            .listen
            .trim()
            .parse::<SocketAddr>()
            .with_context(|| format!("metrics.listen is invalid: `{}`", self.metrics.listen))?;

        validate_log_level(&self.logging.level)?;

        Ok(())
    }
}

impl Default for AppCfg {
    fn default() -> Self {
        let cfg: Self = serde_yaml::from_str(include_str!("../../config/default.yaml"))
            .expect("embedded default config must parse");
        cfg.validate()
            .expect("embedded default config must be valid");
        cfg
    }
}

fn validate_priority(name: &str, value: u8) -> Result<()> {
    if value > 10 {
        bail!("{name} must be between 0 and 10, got {value}");
    }
    Ok(())
}

fn validate_log_level(level: &str) -> Result<()> {
    let normalized = level.trim().to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "off"
    ) {
        Ok(())
    } else {
        bail!("logging.level is invalid: `{level}`");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        AppCfg::default().validate().expect("default config");
    }

    #[test]
    fn rejects_unknown_mode() {
        let cfg = AppCfg {
            mode: "block".to_string(),
            ..AppCfg::default()
        };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("mode"));
    }

    #[test]
    fn rejects_zero_timeout() {
        let base = AppCfg::default();
        let scan = ScanCfg {
            timeout_ms: 0,
            ..base.scan.clone()
        };
        let cfg = AppCfg { scan, ..base };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn rejects_bad_metrics_address() {
        let base = AppCfg::default();
        let metrics = MetricsCfg {
            listen: "127.0.0.1".to_string(),
        };
        let cfg = AppCfg { metrics, ..base };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("metrics.listen"));
    }
}
