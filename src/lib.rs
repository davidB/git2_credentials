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
mod ssh_config;

#[cfg(feature = "ui4dialoguer")]
pub mod ui4dialoguer;

use failure::Error;
use git2;

pub struct CredentialHandler {
    usernames: Vec<String>,
    ssh_attempts_count: usize,
    username_attempts_count: usize,
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
        let mut usernames = Vec::new();
        usernames.push("".to_string()); //default
        usernames.push("git".to_string());
        if let Ok(s) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
            usernames.push(s);
        }

        // let mut cred_helper = git2::CredentialHelper::new(url);
        // cred_helper.config(cfg);
        // if let Some(ref s) = cred_helper.username {
        //     usernames.push(s.clone());
        // }

        CredentialHandler {
            usernames,
            ssh_attempts_count: 2,
            username_attempts_count: 0,
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
            return match self.usernames.get(idx).map(|s| &s[..]) {
                Some("") if username.is_none() => {
                    Err(git2::Error::from_str("gonna try usernames later"))
                }
                Some("") => git2::Cred::username(&username.unwrap_or("")),
                Some(s) => git2::Cred::username(&s),
                _ => Err(git2::Error::from_str("no more username to try")),
            };
        }

        // An "SSH_KEY" authentication indicates that we need some sort of SSH
        // authentication. This can currently either come from the ssh-agent
        // process or from a raw in-memory SSH key. Cargo only supports using
        // ssh-agent currently.
        //
        // If we get called with this then the only way that should be possible
        // is if a username is specified in the URL itself (e.g., `username` is
        // Some), hence the unwrap() here. We try custom usernames down below.
        if allowed.contains(git2::CredentialType::SSH_KEY) {
            // If ssh-agent authentication fails, libgit2 will keep
            // calling this callback asking for other authentication
            // methods to try. Make sure we only try ssh-agent once.
            self.ssh_attempts_count = (self.ssh_attempts_count + 1) % 4;
            // dbg!(self.ssh_attempts_count);
            let u = username.unwrap_or("git");
            return match self.ssh_attempts_count {
                0 => cred_from_home_dir(&u),
                1 => git2::Cred::ssh_key_from_agent(&u),
                2 => self.cred_from_ssh_config(&u),
                _ => Err(git2::Error::from_str("try with an other username")),
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
                match self.ui.ask_user_password(username.unwrap_or("")) {
                    Ok((user, password)) => {
                        return git2::Cred::userpass_plaintext(&user, &password)
                    }
                    Err(_) => (), //FIXME give a feeback instead of ignore
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

    fn cred_from_ssh_config(&self, username: &str) -> Result<git2::Cred, git2::Error> {
        let (key, passphrase) = ssh_config::get_ssh_key_and_passphrase(self.ui.as_ref());
        match key {
            Some(k) => {
                git2::Cred::ssh_key(username, None, &k, passphrase.as_ref().map(String::as_str))
            }
            None => Err(git2::Error::from_str(
                "failed authentication for repository",
            )),
        }
    }
}

fn cred_from_home_dir(username: &str) -> Result<git2::Cred, git2::Error> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| git2::Error::from_str("could not get home directory"))?;
    let ssh_dir = home_dir.join(".ssh");

    git2::Cred::ssh_key(
        username,
        Some(&ssh_dir.join("id_rsa.pub")),
        &ssh_dir.join("id_rsa"),
        None,
    )
}

pub trait CredentialUI {
    fn ask_user_password(&self, username: &str) -> Result<(String, String), Error>;
    fn ask_ssh_passphrase(&self, passphrase_prompt: &str) -> Result<String, Error>;
}
