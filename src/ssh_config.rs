// based on https://github.com/aerys/gpm/blob/master/src/gpm/ssh.rs
use crate::CredentialUI;
use dirs;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path;

fn find_default_ssh_key() -> Option<path::PathBuf> {
    dirs::home_dir().and_then(|home_path| {
        let mut ssh_path = home_path.clone();
        ssh_path.push(".ssh");
        vec!["id_rsa", "id_ed25519"].iter().find_map(|f| {
            let p = ssh_path.join(f);
            if p.exists() && p.is_file() {
                Some(p)
            } else {
                None
            }
        })
    })
}

pub(crate) fn get_ssh_key_and_passphrase(
    ui: &dyn CredentialUI,
) -> (Option<path::PathBuf>, Option<String>) {
    let key = find_default_ssh_key();
    match key {
        Some(key_path) => {
            // debug!("authenticate with private key located in {:?}", key_path);

            let mut f = fs::File::open(key_path.to_owned()).unwrap();
            let mut key = String::new();

            f.read_to_string(&mut key)
                .expect("unable to read SSH key from file");
            f.seek(io::SeekFrom::Start(0)).unwrap();

            (
                Some(key_path.to_owned()),
                ui.ask_ssh_passphrase(&format!(
                    "Enter passphrase for key '{}'",
                    key_path.to_string_lossy()
                ))
                .ok(),
            )
        }
        None => {
            // warn!("unable to get private key for host {}", &host);
            (None, None)
        }
    }
}
