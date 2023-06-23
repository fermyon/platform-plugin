use std::io::Write;
use std::io::stdin;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use hippo::{Client, ConnectionInfo};
use serde::Deserialize;
use serde::Serialize;
use tracing::log;
use url::Url;


use crate::opts::{
    PLATFORM_SERVER_URL_OPT, PLATFORM_URL_ENV, DEPLOYMENT_ENV_NAME_ENV, INSECURE_OPT, SPIN_AUTH_TOKEN, HIPPO_USERNAME, HIPPO_PASSWORD, BINDLE_SERVER_URL_OPT, BINDLE_URL_ENV, BINDLE_USERNAME, BINDLE_PASSWORD,
    TOKEN,
};

const DEFAULT_PLATFORM_URL: &str = "https://127.0.0.1:5309/";

/// Log into the Fermyon self-hosted Platform.
#[derive(Parser, Debug)]
pub struct LoginCommand {
    /// URL of bindle server
    #[clap(
        name = BINDLE_SERVER_URL_OPT,
        long = "bindle-server",
        env = BINDLE_URL_ENV,
    )]
    pub bindle_server_url: Option<String>,

    /// Basic http auth username for the bindle server
    #[clap(
        name = BINDLE_USERNAME,
        long = "bindle-username",
        env = BINDLE_USERNAME,
        requires = BINDLE_PASSWORD
    )]
    pub bindle_username: Option<String>,

    /// Basic http auth password for the bindle server
    #[clap(
        name = BINDLE_PASSWORD,
        long = "bindle-password",
        env = BINDLE_PASSWORD,
        requires = BINDLE_USERNAME
    )]
    pub bindle_password: Option<String>,

    /// Ignore server certificate errors.
    #[clap(
        name = INSECURE_OPT,
        short = 'k',
        long = "insecure",
        takes_value = false,
    )]
    pub insecure: bool,

    /// URL of the Fermyon self-hosted Platform instance.
    #[clap(
        name = PLATFORM_SERVER_URL_OPT,
        long = "url",
        env = PLATFORM_URL_ENV,
        default_value = DEFAULT_PLATFORM_URL,
        value_parser = parse_url,
    )]
    pub hippo_server_url: url::Url,

    /// Hippo username
    #[clap(
        name = HIPPO_USERNAME,
        long = "username",
        env = HIPPO_USERNAME,
        requires = HIPPO_PASSWORD,
    )]
    pub hippo_username: Option<String>,

    /// Hippo password
    #[clap(
        name = HIPPO_PASSWORD,
        long = "password",
        env = HIPPO_PASSWORD,
        requires = HIPPO_USERNAME,
    )]
    pub hippo_password: Option<String>,

    /// Auth Token
    #[clap(
        name = TOKEN,
        long = "token",
        env = SPIN_AUTH_TOKEN,
    )]
    pub token: Option<String>,

    // authentication method used for logging in (username|token)
    #[clap(
        name = "auth-method",
        long = "auth-method",
        env = "AUTH_METHOD",
        arg_enum
    )]
    pub method: Option<AuthMethod>,

    /// Save the login details under the specified name instead of making them
    /// the default. Use named environments with `spin platform deploy --environment-name <name>`.
    #[clap(
        name = "environment-name",
        long = "environment-name",
        env = DEPLOYMENT_ENV_NAME_ENV
    )]
    pub deployment_env_id: Option<String>,

    /// List saved logins.
    #[clap(
        name = "list",
        long = "list",
        takes_value = false,
        conflicts_with = "environment-name",
    )]
    pub list: bool,
}

fn parse_url(url: &str) -> Result<url::Url> {
    let mut url = Url::parse(url).map_err(|error| {
        anyhow::format_err!(
            "URL should be fully qualified in the format \"https://cloud-instance.com\". Error: {}",
            error
        )
    })?;
    // Ensure path ends with '/' so join works properly
    if !url.path().ends_with('/') {
        url.set_path(&(url.path().to_string() + "/"));
    }
    Ok(url)
}

impl LoginCommand {
    pub async fn run(&self) -> Result<()> {
        if self.list
        {
            self.run_list().await?
        }

        self.run_interactive_login().await
    }

    async fn run_list(&self) -> Result<()> {
        let root = config_root_dir()?;

        ensure(&root)?;

        let json_file_stems = std::fs::read_dir(&root)
            .with_context(|| format!("Failed to read config directory {}", root.display()))?
            .filter_map(environment_name_from_path)
            .collect::<Vec<_>>();

        for s in json_file_stems {
            println!("{}", s);
        }

        Ok(())
    }

    async fn run_interactive_login(&self) -> Result<()> {
        let login_connection = match self.auth_method() {
            AuthMethod::Token => self.login_using_token().await?,
            AuthMethod::UsernameAndPassword => self.run_interactive_basic_login().await?,
        };
        self.save_login_info(&login_connection)
    }

    async fn run_interactive_basic_login(&self) -> Result<LoginConnection> {
        let username = prompt_if_not_provided(&self.hippo_username, "Hippo username")?;
        let password = match &self.hippo_password {
            Some(password) => password.to_owned(),
            None => {
                print!("Hippo password: ");
                std::io::stdout().flush()?;
                rpassword::read_password()
                    .expect("unable to read user input")
                    .trim()
                    .to_owned()
            }
        };

        let bindle_url = prompt_if_not_provided(&self.bindle_server_url, "Bindle URL")?;

        // If Bindle URL was provided and Bindle username and password were not, assume Bindle
        // is unauthenticated.  If Bindle URL was prompted for, or Bindle username or password
        // is provided, ask the user.
        let mut bindle_username = self.bindle_username.clone();
        let mut bindle_password = self.bindle_password.clone();

        let unauthenticated_bindle_server_provided = self.bindle_server_url.is_some()
            && self.bindle_username.is_none()
            && self.bindle_password.is_none();
        if !unauthenticated_bindle_server_provided {
            let bindle_username_text = prompt_if_not_provided(
                &self.bindle_username,
                "Bindle username (blank for unauthenticated)",
            )?;
            bindle_username = if bindle_username_text.is_empty() {
                None
            } else {
                Some(bindle_username_text)
            };
            bindle_password = match bindle_username {
                None => None,
                Some(_) => Some(prompt_if_not_provided(
                    &self.bindle_password,
                    "Bindle password",
                )?),
            };
        }

        // log in with username/password
        let token = match Client::login(
            &Client::new(ConnectionInfo {
                url: self.hippo_server_url.to_string(),
                danger_accept_invalid_certs: self.insecure,
                api_key: None,
            }),
            username,
            password,
        )
        .await
        {
            Ok(token_info) => token_info,
            Err(err) => return Err(err),
        };

        Ok(LoginConnection {
            url: self.hippo_server_url.clone(),
            danger_accept_invalid_certs: self.insecure,
            token: token.token.unwrap_or_default(),
            expiration: token.expiration,
            bindle_url: Some(bindle_url),
            bindle_username,
            bindle_password,
        })
    }

    async fn login_using_token(&self) -> Result<LoginConnection> {
        // check that the user passed in a token
        let token = match self.token.clone() {
            Some(t) => t,
            None => return Err(anyhow::anyhow!(format!("No personal access token was provided. Please provide one using either ${} or --{}.", SPIN_AUTH_TOKEN, TOKEN.to_lowercase()))),
        };

        // Validate the token by calling list_apps API until we have a user info API
        Client::new(ConnectionInfo {
            url: self.hippo_server_url.to_string(),
            danger_accept_invalid_certs: self.insecure,
            api_key: Some(token.clone()),
        })
        .list_apps()
        .await
        .context("Login using the provided personal access token failed. Run `spin platform login` or create a new token using the Fermyon self-hosted Platform user interface.")?;

        Ok(self.login_connection_for_token(token))
    }

    fn login_connection_for_token(&self, token: String) -> LoginConnection {
        LoginConnection {
            url: self.hippo_server_url.clone(),
            danger_accept_invalid_certs: self.insecure,
            token,
            expiration: None,
            bindle_url: self.bindle_server_url.clone(),
            bindle_username: self.bindle_username.clone(),
            bindle_password: self.bindle_password.clone(),
        }
    }

    fn config_file_path(&self) -> Result<PathBuf> {
        let root = config_root_dir()?;

        ensure(&root)?;

        let file_stem = match &self.deployment_env_id {
            None => "config",
            Some(id) => id,
        };
        let file = format!("{}.json", file_stem);

        let path = root.join(file);

        Ok(path)
    }

    fn auth_method(&self) -> AuthMethod {
        if let Some(method) = &self.method {
            method.clone()
        } else if self.token.is_some() {
            AuthMethod::Token
        } else {
            AuthMethod::UsernameAndPassword
        }
    }

    fn save_login_info(&self, login_connection: &LoginConnection) -> Result<(), anyhow::Error> {
        let path = self.config_file_path()?;
        std::fs::write(path, serde_json::to_string_pretty(login_connection)?)?;
        Ok(())
    }
}

fn config_root_dir() -> Result<PathBuf, anyhow::Error> {
    let root = dirs::config_dir()
        .context("Cannot find configuration directory")?
        .join("fermyon");
    Ok(root)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginConnection {
    pub url: Url,
    pub danger_accept_invalid_certs: bool,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub expiration: Option<String>,
    pub bindle_url: Option<String>,
    pub bindle_username: Option<String>,
    pub bindle_password: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct LoginCloudError {
    title: String,
    detail: String,
}

/// Ensure the root directory exists, or else create it.
fn ensure(root: &PathBuf) -> Result<()> {
    log::trace!("Ensuring root directory {:?}", root);
    if !root.exists() {
        log::trace!("Creating configuration root directory `{}`", root.display());
        std::fs::create_dir_all(root).with_context(|| {
            format!(
                "Failed to create configuration root directory `{}`",
                root.display()
            )
        })?;
    } else if !root.is_dir() {
        bail!(
            "Configuration root `{}` already exists and is not a directory",
            root.display()
        );
    } else {
        log::trace!(
            "Using existing configuration root directory `{}`",
            root.display()
        );
    }

    Ok(())
}

/// The method by which to authenticate the login.
#[derive(clap::ArgEnum, Clone, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    #[clap(name = "token")]
    Token,
    #[clap(name = "username")]
    UsernameAndPassword,
}

fn environment_name_from_path(dir_entry: std::io::Result<std::fs::DirEntry>) -> Option<String> {
    let json_ext = std::ffi::OsString::from("json");
    let default_name = "(default)";
    match dir_entry {
        Err(_) => None,
        Ok(de) => {
            if is_file_with_extension(&de, &json_ext) {
                de.path().file_stem().map(|stem| {
                    let s = stem.to_string_lossy().to_string();
                    if s == "config" {
                        default_name.to_owned()
                    } else {
                        s
                    }
                })
            } else {
                None
            }
        }
    }
}

fn is_file_with_extension(de: &std::fs::DirEntry, extension: &std::ffi::OsString) -> bool {
    match de.file_type() {
        Err(_) => false,
        Ok(t) => {
            if t.is_file() {
                de.path().extension() == Some(extension)
            } else {
                false
            }
        }
    }
}

fn prompt_if_not_provided(provided: &Option<String>, prompt_text: &str) -> Result<String> {
    match provided {
        Some(value) => Ok(value.to_owned()),
        None => {
            print!("{}: ", prompt_text);
            std::io::stdout().flush()?;
            let mut input = String::new();
            stdin()
                .read_line(&mut input)
                .expect("unable to read user input");
            Ok(input.trim().to_owned())
        }
    }
}

#[test]
fn parse_url_ensures_trailing_slash() {
    let url = parse_url("https://localhost:12345/foo/bar").unwrap();
    assert_eq!(url.to_string(), "https://localhost:12345/foo/bar/");
}
