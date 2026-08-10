//! Value-safe loading for secrets supplied directly or through runtime files.

use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretInputError {
    InvalidEnvironment { variable: String },
    UnreadableFile { variable: String },
    EmptyFile { variable: String },
}

impl fmt::Display for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvironment { variable } => {
                write!(formatter, "{variable} is not valid Unicode")
            }
            Self::UnreadableFile { variable } => {
                write!(formatter, "{variable} does not name a readable UTF-8 file")
            }
            Self::EmptyFile { variable } => {
                write!(formatter, "{variable} contains an empty secret")
            }
        }
    }
}

impl std::error::Error for SecretInputError {}

/// Load an optional secret from `<NAME>_FILE` or, for compatibility, `<NAME>`.
///
/// A non-empty file variable wins even when the direct variable is also set.
/// File content loses exactly one trailing LF or CRLF line ending; every other
/// byte is preserved. Errors identify the configuration variable without
/// exposing the path or secret material.
pub fn optional_secret(name: &str) -> Result<Option<String>, SecretInputError> {
    resolve_optional_secret(name, environment_value)
}

fn environment_value(name: &str) -> Result<Option<String>, SecretInputError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretInputError::InvalidEnvironment {
            variable: name.to_string(),
        }),
    }
}

fn resolve_optional_secret<F>(name: &str, lookup: F) -> Result<Option<String>, SecretInputError>
where
    F: Fn(&str) -> Result<Option<String>, SecretInputError>,
{
    let file_variable = format!("{name}_FILE");
    if let Some(path) = lookup(&file_variable)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let contents = std::fs::read_to_string(Path::new(&path)).map_err(|_| {
            SecretInputError::UnreadableFile {
                variable: file_variable.clone(),
            }
        })?;
        let secret = without_one_trailing_line_ending(contents);
        if secret.is_empty() {
            return Err(SecretInputError::EmptyFile {
                variable: file_variable,
            });
        }
        return Ok(Some(secret));
    }

    Ok(lookup(name)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn without_one_trailing_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn test_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pharos-secret-input-{}-{}",
            std::process::id(),
            TEST_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write secret input fixture");
        path
    }

    fn resolve(values: &[(&str, String)]) -> Result<Option<String>, SecretInputError> {
        let values = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        resolve_optional_secret("PHAROS_TEST_TOKEN", |name| Ok(values.get(name).cloned()))
    }

    #[test]
    fn file_wins_and_removes_exactly_one_line_ending() {
        let path = test_file(" file-token \r\n");
        let loaded = resolve(&[
            ("PHAROS_TEST_TOKEN", "environment-token".to_string()),
            (
                "PHAROS_TEST_TOKEN_FILE",
                path.to_string_lossy().into_owned(),
            ),
        ])
        .expect("load file-backed secret");

        assert_eq!(loaded.as_deref(), Some(" file-token "));
        std::fs::remove_file(path).expect("remove secret input fixture");
    }

    #[test]
    fn a_second_trailing_newline_is_preserved() {
        let path = test_file("file-token\n\n");
        let loaded = resolve(&[(
            "PHAROS_TEST_TOKEN_FILE",
            path.to_string_lossy().into_owned(),
        )])
        .expect("load file-backed secret");

        assert_eq!(loaded.as_deref(), Some("file-token\n"));
        std::fs::remove_file(path).expect("remove secret input fixture");
    }

    #[test]
    fn unreadable_file_fails_without_falling_back_to_environment() {
        let missing = std::env::temp_dir().join(format!(
            "pharos-secret-input-missing-{}-{}",
            std::process::id(),
            TEST_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let error = resolve(&[
            ("PHAROS_TEST_TOKEN", "environment-token".to_string()),
            (
                "PHAROS_TEST_TOKEN_FILE",
                missing.to_string_lossy().into_owned(),
            ),
        ])
        .expect_err("configured file must fail closed");

        assert_eq!(
            error,
            SecretInputError::UnreadableFile {
                variable: "PHAROS_TEST_TOKEN_FILE".to_string()
            }
        );
        assert!(!error.to_string().contains("environment-token"));
        assert!(!error
            .to_string()
            .contains(&missing.to_string_lossy().into_owned()));
    }

    #[test]
    fn empty_file_fails_specifically() {
        let path = test_file("\n");
        let error = resolve(&[(
            "PHAROS_TEST_TOKEN_FILE",
            path.to_string_lossy().into_owned(),
        )])
        .expect_err("empty file must fail closed");

        assert_eq!(
            error,
            SecretInputError::EmptyFile {
                variable: "PHAROS_TEST_TOKEN_FILE".to_string()
            }
        );
        std::fs::remove_file(path).expect("remove secret input fixture");
    }

    #[test]
    fn direct_environment_value_remains_trimmed_for_compatibility() {
        assert_eq!(
            resolve(&[("PHAROS_TEST_TOKEN", " environment-token ".to_string())])
                .expect("load direct secret")
                .as_deref(),
            Some("environment-token")
        );
        assert_eq!(resolve(&[]).expect("missing secret is optional"), None);
    }
}
