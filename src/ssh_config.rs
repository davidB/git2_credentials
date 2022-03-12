// based on https://github.com/aerys/gpm/blob/master/src/gpm/ssh.rs
use crate::CredentialUI;
use dirs;
use pest::Parser;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path;

/// Simple Parser for `.ssh/config` files genereted by pest and the grammar defined into `ssh_config.pest`
/// (follow the syntax defined at [Syntax of pest parsers - A thoughtful introduction to the pest parser](https://pest.rs/book/grammars/syntax.html))
/// use the online editor to experiment [pest. The Elegant Parser](https://pest.rs/#editor)
#[derive(Parser)]
#[grammar = "ssh_config.pest"]
#[allow(dead_code)]
pub struct SSHConfigParser;

fn find_ssh_key_in_ssh_config(host: &str) -> Result<Option<String>, git2::Error> {
    match read_ssh_config_as_string()? {
        Some(content) => find_ssh_key_for_host_in_config(host, &content),
        _ => Ok(None),
    }
}

fn read_ssh_config_as_string() -> Result<Option<String>, git2::Error> {
    dirs::home_dir()
        .map(|home_path| {
            let mut ssh_config_path = path::PathBuf::from(home_path);

            ssh_config_path.push(".ssh");
            ssh_config_path.push("config");
            ssh_config_path
        })
        .filter(|p| p.exists())
        .map(|ssh_config_path| {
            let mut f = fs::File::open(ssh_config_path.to_owned()).map_err(|source| {
                git2::Error::from_str(&format!(
                    "failed to open {:?}: {:#?}",
                    ssh_config_path, source
                ))
            })?;
            let mut contents = String::new();

            f.read_to_string(&mut contents).map_err(|source| {
                git2::Error::from_str(&format!(
                    "failed to read {:?}: {:#?}",
                    ssh_config_path, source
                ))
            })?;
            Ok(Some(contents))
        })
        .unwrap_or(Ok(None))
}

fn find_ssh_key_for_host_in_config(
    host: &str,
    ssh_config_str: &str,
) -> Result<Option<String>, git2::Error> {
    // trace!("parsing {:?} to find host {}", ssh_config_path, host);

    let pairs = SSHConfigParser::parse(Rule::config, &ssh_config_str).map_err(|source| {
        git2::Error::from_str(&format!("failed to parse .ssh/config: {:#?}", source))
    })?;
    for pair in pairs {
        let mut inner_pairs = pair.into_inner().flatten();
        let pattern = inner_pairs.find(|p| -> bool {
            let pattern_str = String::from(p.as_str());

            match pattern_str.contains("*") {
                true => {
                    // convert the globbing pattern to a regexp
                    let pattern_str = pattern_str.replace(".", "\\.");
                    let pattern_str = pattern_str.replace("*", ".*");
                    let regexp = regex::Regex::new(pattern_str.as_str()).expect(&format!(
                        "failed to parse converted regexp({}) from .ssh/config",
                        pattern_str
                    ));
                    p.as_rule() == Rule::pattern && regexp.is_match(host)
                }
                false => p.as_rule() == Rule::pattern && p.as_str() == host,
            }
        });

        match pattern {
            Some(pattern) => {
                // trace!("found matching host with pattern {:?}", pattern.as_str());

                let options = inner_pairs.filter(|p| -> bool { p.as_rule() == Rule::option });

                for option in options {
                    let mut key_and_value = option.into_inner().flatten();
                    let key = key_and_value
                        .find(|p| -> bool { p.as_rule() == Rule::key })
                        .ok_or_else(|| {
                            git2::Error::from_str(&format!(
                                "key not found on .ssh/config for host {}",
                                pattern.as_str()
                            ))
                        })?;
                    let value = key_and_value
                        .find(|p| -> bool { p.as_rule() == Rule::value_unquoted })
                        .ok_or_else(|| {
                            git2::Error::from_str(&format!(
                                "value not found on .ssh/config for host {} and key '{}'",
                                pattern.as_str(),
                                key
                            ))
                        })?;

                    if key.as_str().eq_ignore_ascii_case("IdentityFile") {
                        let path = value.as_str().to_string();

                        // trace!("found IdentityFile option with value {:?}", path);
                        return Ok(Some(path));
                    }
                }
            }
            None => continue,
        };
    }
    Ok(None)
}

pub(crate) fn find_ssh_key_candidates(
    host: Option<&str>,
) -> Result<Vec<path::PathBuf>, git2::Error> {
    // candidates in the same order than the list from IdentityFile in ssh_config man page.
    let mut candidates = vec![];
    // first the candidates from .ssh/config for the target host
    if let Some(host) = host {
        if let Some(key_for_host) = find_ssh_key_in_ssh_config(host)? {
            candidates.push(key_for_host.to_string());
        }
    }
    // push default candidates in the same order than the list from IdentityFile in ssh_config man page.
    candidates.extend_from_slice(&[
        "~/.ssh/id_dsa".to_string(),
        "~/.ssh/id_ecdsa".to_string(),
        "~/.ssh/id_ecdsa_sk".to_string(),
        "~/.ssh/id_ed25519".to_string(),
        "~/.ssh/id_ed25519_sk".to_string(),
        "~/.ssh/id_rsa".to_string(),
    ]);
    // "~" should be expanded
    let hds = dirs::home_dir()
        .map(|p| p.display().to_string())
        .ok_or_else(|| git2::Error::from_str("could not get home directory"))?;

    let candidates_path = candidates
        .iter()
        .map(|p| path::PathBuf::from(p.replace("~", &hds)))
        .filter(|p| p.exists() && p.is_file())
        .collect();
    Ok(candidates_path)
}

pub(crate) fn get_ssh_key_and_passphrase(
    candidates: &Vec<path::PathBuf>,
    candidate_idx: usize,
    ui: &dyn CredentialUI,
) -> Result<(Option<path::PathBuf>, Option<String>), git2::Error> {
    let key = candidates.get(candidate_idx);
    match key {
        Some(key_path) => {
            // debug!("authenticate with private key located in {:?}", key_path);

            let mut f = fs::File::open(key_path.to_owned()).unwrap();
            let mut key = String::new();

            f.read_to_string(&mut key).map_err(|source| {
                git2::Error::from_str(&format!("failed to read {:?}: {:#?}", key_path, source))
            })?;
            f.seek(io::SeekFrom::Start(0)).map_err(|source| {
                git2::Error::from_str(&format!(
                    "failed to set seek to 0 in {:?}: {:#?}",
                    key_path, source
                ))
            })?;
            Ok((
                Some(key_path.to_owned()),
                ui.ask_ssh_passphrase(&format!(
                    "Enter passphrase for key '{}'",
                    key_path.to_string_lossy()
                ))
                .ok(),
            ))
        }
        None => {
            // warn!("unable to get private key for host {}", &host);
            Ok((None, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ssh_config_parser_no_failure() -> Result<(), Box<dyn std::error::Error>> {
        let ssh_config_str = r#"
Host x
    ff fff
    zz " fofo bar "
Host z
    z1 v
        "#;
        SSHConfigParser::parse(Rule::config, &ssh_config_str)?;
        Ok(())
    }
    #[test]
    fn find_ssh_key_for_host_in_config_empty() {
        let actual = find_ssh_key_for_host_in_config("github.com", r#""#);
        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_not_defined() {
        let actual = find_ssh_key_for_host_in_config(
            "github.com",
            r#"
host bitbucket.org
        IdentityFile ~/.ssh/id_rsa_bitbucket
        IdentitiesOnly "yes"
        "#,
        );
        assert_eq!(actual, Ok(None));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_defined() {
        let actual = find_ssh_key_for_host_in_config(
            "bitbucket.org",
            r#"
host bitbucket.org
        IdentityFile ~/.ssh/id_rsa_bitbucket
        IdentitiesOnly "yes"
        "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/id_rsa_bitbucket".to_string())));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_defined_multi_match() {
        let actual = find_ssh_key_for_host_in_config(
            "bitbucket.org",
            r#"
host bitbucket.org
        IdentityFile ~/.ssh/id_rsa_bitbucket
        IdentitiesOnly "yes"
Host b*
        IdentityFile ~/.ssh/id_rsa_b
        IdentitiesOnly "yes"
        "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/id_rsa_bitbucket".to_string())));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_defined_pattern() {
        let actual = find_ssh_key_for_host_in_config(
            "bitbucket.org",
            r#"
Host b*
            IdentityFile ~/.ssh/id_rsa_b
            IdentitiesOnly "yes"
host bitbucket.org
        IdentityFile ~/.ssh/id_rsa_bitbucket
        IdentitiesOnly "yes"

        "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/id_rsa_b".to_string())));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_nofailed_on_kexalgorithms() {
        let actual = find_ssh_key_for_host_in_config(
            "github.com",
            r#"
KexAlgorithms +diffie-hellman-group1-sha1

Host github.com
    HostName github.com
    IdentityFile ~/.ssh/me

Host *
    ServerAliveInterval 1
    ServerAliveCountMax 300
        "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/me".to_string())));
    }

    #[test]
    fn find_ssh_key_for_host_in_config_nofailed_on_comments() {
        let actual = find_ssh_key_for_host_in_config(
            "bitbucket.org",
            r#"
# comment before
Host bitbucket.org
        # comments
        IdentityFile ~/.ssh/me # comments
        IdentitiesOnly "yes" 
# comments after last host ok too
        "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/me".to_string())));
    }

    #[test]
    fn case_insensitive_keys() {
        let actual = find_ssh_key_for_host_in_config(
            "bitbucket.org",
            r#"
    host bitbucket.org
            identityFILE ~/.ssh/me
            IdentitiesOnly "yes"
            "#,
        );
        assert_eq!(actual, Ok(Some("~/.ssh/me".to_string())));
    }
}
