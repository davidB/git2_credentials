//! Provide credential function to used with [git2](https://crates.io/crates/git2)::[RemoteCallbacks.credentials](https://docs.rs/git2/0.8.0/git2/struct.RemoteCallbacks.html#method.credentials)
//!
//! Usage:
//! ```rust
//! use git2;
//! use git2_credentials::CredentialHandler;
//! use tempfile;
//!
//! let mut cb = git2::RemoteCallbacks::new();
//! let git_config = git2::Config::open_default().unwrap();
//! let mut ch = CredentialHandler::new(git_config);
//! cb.credentials(move |url, username, allowed| ch.try_next_credential(url, username, allowed));
//!
//! // let mut fo = git2::FetchOptions::new();
//! // fo.remote_callbacks(cb)
//! //     .download_tags(git2::AutotagOption::All)
//! //     .update_fetchhead(true);
//! // let dst = tempfile::tempdir().unwrap();
//! // std::fs::create_dir_all(&dst.as_ref()).unwrap();
//! // git2::build::RepoBuilder::new()
//! //     .branch("master")
//! //     .fetch_options(fo)
//! //     .clone("git@github.com:davidB/git2_credentials.git", dst.as_ref()).unwrap();
//! ```
#[macro_use]
extern crate pest_derive;

pub use git2;

mod ssh_config;

#[cfg(feature = "ui4dialoguer")]
pub mod ui4dialoguer;

use std::error::Error;

pub struct CredentialHandler {
    username_attempts_count: usize,
    username_candidates: Vec<String>,
    ssh_attempts_count: usize,
    ssh_key_candidates: Vec<std::path::PathBuf>,
    cred_helper_bad: Option<bool>,
    cfg: git2::Config,
    ui: Box<dyn CredentialUI>,
}

// implemention based on code & comment from cargo
// https://github.com/rust-lang/cargo/blob/master/src/cargo/sources/git/utils.rs#L415-L628
// License APACHE
// but adapted to not use wrapper over function like withXxx(FnMut), a more OO approach
impl CredentialHandler {
    #[cfg(feature = "ui4dialoguer")]
    pub fn new(cfg: git2::Config) -> Self {
        use ui4dialoguer::CredentialUI4Dialoguer;
        Self::new_with_ui(cfg, Box::new(CredentialUI4Dialoguer {}))
    }

    pub fn new_with_ui(cfg: git2::Config, ui: Box<dyn CredentialUI>) -> Self {
        CredentialHandler {
            username_attempts_count: 0,
            username_candidates: vec![],
            ssh_attempts_count: 0,
            ssh_key_candidates: vec![],
            cred_helper_bad: None,
            cfg,
            ui,
        }
    }

    /// Prepare the authentication callbacks for cloning a git repository.
    ///
    /// The main purpose of this function is to construct the "authentication
    /// callback" which is used to clone a repository. This callback will attempt to
    /// find the right authentication on the system (maybe with user input) and will
    /// guide libgit2 in doing so.
    ///
    /// The callback is provided `allowed` types of credentials, and we try to do as
    /// much as possible based on that:
    ///
    /// - Prioritize SSH keys from the local ssh agent as they're likely the most
    ///   reliable. The username here is prioritized from the credential
    ///   callback, then from whatever is configured in git itself, and finally
    ///   we fall back to the generic user of `git`. If no ssh agent try to use
    ///   the default key ($HOME/.ssh/id_rsa, $HOME/.ssh/id_ed25519)
    ///
    /// - If a username/password is allowed, then we fallback to git2-rs's
    ///   implementation of the credential helper. This is what is configured
    ///   with `credential.helper` in git, and is the interface for the macOS
    ///   keychain, for example. Else ask (on ui) the for username and password.
    ///
    /// - After the above two have failed, we just kinda grapple attempting to
    ///   return *something*.
    ///
    /// If any form of authentication fails, libgit2 will repeatedly ask us for
    /// credentials until we give it a reason to not do so. To ensure we don't
    /// just sit here looping forever we keep track of authentications we've
    /// attempted and we don't try the same ones again.
    pub fn try_next_credential(
        &mut self,
        url: &str,
        username: Option<&str>,
        allowed: git2::CredentialType,
    ) -> Result<git2::Cred, git2::Error> {
        // dbg!(allowed);

        // libgit2's "USERNAME" authentication actually means that it's just
        // asking us for a username to keep going. This is currently only really
        // used for SSH authentication and isn't really an authentication type.
        // The logic currently looks like:
        //
        //      let user = ...;
        //      if (user.is_null())
        //          user = callback(USERNAME, null, ...);
        //
        //      callback(SSH_KEY, user, ...)
        //
        // So if we're being called here then we know that (a) we're using ssh
        // authentication and (b) no username was specified in the URL that
        // we're trying to clone. We need to guess an appropriate username here,
        // but that may involve a few attempts.
        // (FIXME) Unfortunately we can't switch
        // usernames during one authentication session with libgit2, so to
        // handle this we bail out of this authentication session after setting
        // the flag `ssh_username_requested`, and then we handle this below.
        if allowed.contains(git2::CredentialType::USERNAME) {
            // debug_assert!(username.is_none());
            let idx = self.username_attempts_count;
            self.username_attempts_count += 1;
            if idx == 0 {
                let maybe_host = extract_host(url)?;
                self.username_candidates =
                    ssh_config::find_username_candidates(maybe_host.as_deref())?;
            }
            return match self.username_candidates.get(idx).map(|s| &s[..]) {
                Some(s) => git2::Cred::username(s),
                _ => Err(git2::Error::from_str("no more username to try")),
            };
        }

        // An "SSH_KEY" authentication indicates that we need some sort of SSH
        // authentication. This can currently either come from the ssh-agent
        // process or from a raw in-memory SSH key.
        //
        // If we get called with this then the only way that should be possible
        // is if a username is specified in the URL itself (e.g., `username` is
        // Some), hence the unwrap() here. We try custom usernames down below.
        if allowed.contains(git2::CredentialType::SSH_KEY) {
            // If ssh-agent authentication fails, libgit2 will keep
            // calling this callback asking for other authentication
            // methods to try. Make sure we only try ssh-agent once.
            self.ssh_attempts_count += 1;
            // dbg!(self.ssh_attempts_count);
            let u = username.unwrap_or("git");
            return if self.ssh_attempts_count == 1 {
                git2::Cred::ssh_key_from_agent(u)
            } else {
                if self.ssh_attempts_count == 2 {
                    let maybe_host = extract_host(url)?;
                    self.ssh_key_candidates =
                        ssh_config::find_ssh_key_candidates(maybe_host.as_deref())?;
                }
                let candidate_idx = self.ssh_attempts_count - 2;
                if candidate_idx < self.ssh_key_candidates.len() {
                    self.cred_from_ssh_config(candidate_idx, u)
                } else {
                    Err(git2::Error::from_str("try with an other username"))
                }
            };
        }

        // Sometimes libgit2 will ask for a username/password in plaintext.
        //
        // If ssh-agent authentication fails, libgit2 will keep calling this
        // callback asking for other authentication methods to try. Check
        // cred_helper_bad to make sure we only try the git credentail helper
        // once, to avoid looping forever.
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT)
            && self.cred_helper_bad.is_none()
        {
            let r = git2::Cred::credential_helper(&self.cfg, url, username);
            self.cred_helper_bad = Some(r.is_err());
            if r.is_err() {
                if let Ok((user, password)) = self.ui.ask_user_password(username.unwrap_or("")) {
                    return git2::Cred::userpass_plaintext(&user, &password);
                }
            }
            return r;
        }

        // I'm... not sure what the DEFAULT kind of authentication is, but seems
        // easy to support?
        if allowed.contains(git2::CredentialType::DEFAULT) {
            return git2::Cred::default();
        }

        // Stop trying
        Err(git2::Error::from_str("no valid authentication available"))
    }

    fn cred_from_ssh_config(
        &self,
        candidate_idx: usize,
        username: &str,
    ) -> Result<git2::Cred, git2::Error> {
        let key = ssh_config::get_ssh_key(&self.ssh_key_candidates, candidate_idx)?;
        match key {
            // try first without passphrase then ask for passphrase to avoid asking for passphrase when not set
            Some(k) => git2::Cred::ssh_key(username, None, &k, None).or_else(|_| {
                let passphrase = self
                    .ui
                    .ask_ssh_passphrase(&format!(
                        "Enter passphrase for key '{}'",
                        k.to_string_lossy()
                    ))
                    .ok()
                    .filter(|v| !v.is_empty());
                git2::Cred::ssh_key(username, None, &k, passphrase.as_deref())
            }),
            None => Err(git2::Error::from_str(
                "failed authentication for repository",
            )),
        }
    }
}

fn extract_host(url: &str) -> Result<Option<String>, git2::Error> {
    // crates url failed to parse `"git@github.com:davidB/git2_credentials.git"`
    // let url = url::Url::parse(&url_normalized).map_err(|source| {
    //     git2::Error::from_str(&format!("failed to parse url '{}': {:#?}", url, source))
    // })?;
    // Ok(url.host().map(|h| h.to_string()))
    let url_re = regex::Regex::new(
        r"^(https?|ssh)://([[:alnum:]:\._-]+@)?(?P<host>[[:alnum:]\._-]+)(:\d+)?/(?P<path>[[:alnum:]\._\-/]+).git$",
    ).map_err(|source| git2::Error::from_str(&format!("failed to parse url '{}': {:#?}", url, source)))?;
    let url_re2 = regex::Regex::new(
        r"^(https?|ssh)://([[:alnum:]:\._-]+@)?(?P<host>[[:alnum:]\._-]+)(:\d+)?/(?P<path>[[:alnum:]\._\-/]+)$",
    ).map_err(|source| git2::Error::from_str(&format!("failed to parse url '{}': {:#?}", url, source)))?;
    let git_re = regex::Regex::new(
        r"^([[:alnum:]:\._-]+@)?(?P<host>[[:alnum:]\._-]+):(?P<path>[[:alnum:]\._\-/]+).git$",
    )
    .map_err(|source| {
        git2::Error::from_str(&format!("failed to parse url '{}': {:#?}", url, source))
    })?;
    let git_re2 = regex::Regex::new(
        r"^([[:alnum:]:\._-]+@)?(?P<host>[[:alnum:]\._-]+):(?P<path>[[:alnum:]\._\-/]+)$",
    )
    .map_err(|source| {
        git2::Error::from_str(&format!("failed to parse url '{}': {:#?}", url, source))
    })?;
    Ok(url_re
        .captures(url)
        .or_else(|| url_re2.captures(url))
        .or_else(|| git_re.captures(url))
        .or_else(|| git_re2.captures(url))
        .map(|caps| caps["host"].to_string()))
}

pub trait CredentialUI {
    fn ask_user_password(&self, username: &str) -> Result<(String, String), Box<dyn Error>>;
    fn ask_ssh_passphrase(&self, passphrase_prompt: &str) -> Result<String, Box<dyn Error>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extract_host() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            extract_host("git@github.com:davidB/git2_credentials.git"),
            Ok(Some("github.com".to_string()))
        );
        assert_eq!(
            extract_host("https://github.com/davidB/git2_credentials.git"),
            Ok(Some("github.com".to_string()))
        );
        assert_eq!(
            extract_host("ssh://aur@aur.archlinux.org/souko.git"),
            Ok(Some("aur.archlinux.org".to_string()))
        );
        assert_eq!(
            extract_host("aur@aur.archlinux.org:souko.git"),
            Ok(Some("aur.archlinux.org".to_string()))
        );
        assert_eq!(
            extract_host("aur.archlinux.org:souko.git"),
            Ok(Some("aur.archlinux.org".to_string()))
        );
        Ok(())
    }
}
