use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub op_program: PathBuf,
    pub fallback_program: PathBuf,
    pub account: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub on_lookup_failure: LookupFailure,
    #[serde(default)]
    pub keys: BTreeMap<String, String>,
}

// What to do when op fails or times out. Its exit status is the same for a
// cancelled prompt and an unreachable 1Password app, so this is a user choice.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LookupFailure {
    // Return a cancellation error: cancelling 1Password never opens a second prompt.
    #[default]
    Cancel,
    // Open the fallback pinentry, e.g. when the 1Password app is not running.
    Prompt,
}

fn default_timeout() -> u64 {
    120
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|_| "cannot read configuration")?;
        let config: Self = toml::from_str(&text).map_err(|_| "invalid TOML configuration")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.op_program.is_absolute() || !self.fallback_program.is_absolute() {
            return Err("op_program and fallback_program must be absolute paths".into());
        }
        if !(1..=3600).contains(&self.timeout_seconds) {
            return Err("timeout_seconds must be between 1 and 3600".into());
        }
        for (grip, reference) in &self.keys {
            if grip.len() != 40
                || !grip
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
            {
                return Err("keys must be uppercase 40-character keygrips".into());
            }
            if !reference.starts_with("op://") || reference.chars().any(char::is_control) {
                return Err(
                    "key values must be op:// secret references without control characters".into(),
                );
            }
        }
        let current =
            std::env::current_exe().map_err(|_| "cannot locate pinentry-op executable")?;
        let fallback = self
            .fallback_program
            .canonicalize()
            .map_err(|_| "cannot locate fallback executable")?;
        if current.canonicalize().ok().as_ref() == Some(&fallback) {
            return Err("fallback_program must not point to pinentry-op".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<Config>(
            "op_program='/op'\nfallback_program='/fallback'\ntimeout_second=4"
        )
        .is_err());
    }

    #[test]
    fn lookup_failure_policy_defaults_to_cancel() {
        let base = "op_program='/op'\nfallback_program='/fallback'\n";
        let config: Config = toml::from_str(base).unwrap();
        assert_eq!(config.on_lookup_failure, LookupFailure::Cancel);
        let config: Config = toml::from_str(&format!("{base}on_lookup_failure='prompt'")).unwrap();
        assert_eq!(config.on_lookup_failure, LookupFailure::Prompt);
        assert!(toml::from_str::<Config>(&format!("{base}on_lookup_failure='fallback'")).is_err());
    }

    #[test]
    fn rejects_relative_executables_and_invalid_keygrips() {
        let mut config: Config =
            toml::from_str("op_program='op'\nfallback_program='/fallback'").unwrap();
        assert!(config.validate().unwrap_err().contains("absolute"));
        config.op_program = "/op".into();
        config
            .keys
            .insert("key-id".into(), "op://vault/item/password".into());
        assert!(config.validate().unwrap_err().contains("keygrips"));
    }
}
