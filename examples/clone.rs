use git2;
use git2_credentials::ui4dialoguer::CredentialUI4Dialoguer;
use git2_credentials::CredentialHandler;
use tempfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cb = git2::RemoteCallbacks::new();
    let git_config = git2::Config::open_default()?;
    let mut ch = CredentialHandler::new_with_ui(git_config, Box::new(CredentialUI4Dialoguer {}));
    //let mut ch = CredentialHandler::new(git_config);
    cb.credentials(move |url, username, allowed| ch.try_next_credential(url, username, allowed));
    let mut fo = git2::FetchOptions::new();
    fo.remote_callbacks(cb)
        .download_tags(git2::AutotagOption::All)
        .update_fetchhead(true);
    let dst = tempfile::tempdir()?;
    std::fs::create_dir_all(&dst.as_ref())?;
    git2::build::RepoBuilder::new()
        .branch("master")
        .fetch_options(fo)
        .clone("git@github.com:davidB/git2_credentials.git", dst.as_ref())?;
    Ok(())
}
