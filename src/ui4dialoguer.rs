use dialoguer::{Input, Password};
use std::error::Error;

pub struct CredentialUI4Dialoguer;

impl crate::CredentialUI for CredentialUI4Dialoguer {
    fn ask_user_password(&self, username: &str) -> Result<(String, String), Box<dyn Error>> {
        let user: String = Input::new()
            .default(username.to_owned())
            .with_prompt("username")
            .interact()?;
        let password: String = Password::new()
            .with_prompt("password (hidden)")
            .allow_empty_password(true)
            .interact()?;
        Ok((user, password))
    }

    fn ask_ssh_passphrase(&self, passphrase_prompt: &str) -> Result<String, Box<dyn Error>> {
        let passphrase: String = Password::new()
            .with_prompt(passphrase_prompt)
            .allow_empty_password(true)
            .interact()?;
        Ok(passphrase)
    }
}
