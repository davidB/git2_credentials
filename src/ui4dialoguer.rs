use dialoguer::Input;
use dialoguer::PasswordInput;
use failure::Error;

pub struct CredentialUI4Dialoguer;

impl crate::CredentialUI for CredentialUI4Dialoguer {
    fn ask_user_password(&self, username: &str) -> Result<(String, String), Error> {
        let user: String = Input::new()
            .default(username.to_owned())
            .with_prompt("username")
            .interact()?;
        let password: String = PasswordInput::new()
            .with_prompt("password (hidden)")
            .allow_empty_password(true)
            .interact()?;
        Ok((user.to_owned(), password.to_owned()))
    }

    fn ask_ssh_passphrase(&self, passphrase_prompt: &str) -> Result<String, Error> {
        let passphrase: String = PasswordInput::new()
            .with_prompt(passphrase_prompt)
            .allow_empty_password(true)
            .interact()?;
        Ok(passphrase.to_owned())
    }
}
