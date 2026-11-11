mod client;
mod decrypt;
mod download;
mod hardware;
mod host;
mod models;
mod profile;
mod runtime;
mod token;

use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use client::{DmmClient, DynError};
use models::{FileManifest, StoredSession};

const DEFAULT_API_BASE_URL: &str = "https://apidgp-gameplayer.games.dmm.com";
const PRODUCT_ID: &str = "gakumas";
const GAME_TYPE: &str = "GCL";

#[derive(Debug, Parser)]
#[command(
    name = "gakumas-launcher",
    version,
    about = "Gakumas launcher: run without arguments to automatically login, download, decrypt, and launch"
)]
struct Cli {
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    #[arg(long, global = true, default_value_t = 8, alias = "concurrency")]
    jobs: usize,
    #[arg(long, global = true)]
    force: bool,
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, global = true)]
    bepinex: Option<PathBuf>,
    #[arg(long, global = true, env = "DMM_API_BASE_URL", default_value = DEFAULT_API_BASE_URL)]
    api_base_url: String,
    #[command(flatten)]
    runtime: runtime::Options,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Login {
        #[arg(long)]
        code: Option<String>,
    },
    Logout,
    Download,
    Decrypt,
    Prepare,
    Launch,
}

fn main() {
    if host::should_run_as_host() {
        host::run_and_exit();
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to initialize tokio runtime");

    if let Err(error) = rt.block_on(run()) {
        if error.to_string() == "canceled" {
            eprintln!("Canceled.");
            std::process::exit(130);
        }
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    let mut cli = Cli::parse();
    let config = token::load_config()?;
    cli.runtime.apply_config(&config);
    let game_dir = cli
        .dir
        .or(config.dir)
        .unwrap_or_else(|| PathBuf::from("game"));
    let bepinex = cli.bepinex.or(config.bepinex);

    if let Some(Commands::Decrypt) = &cli.command {
        fs::create_dir_all(&game_dir)?;
        let root = fs::canonicalize(&game_dir)?;
        return runtime::decrypt(&root, &cli.runtime, cli.force).await;
    }

    let store = token::TokenStore::new()?;
    let session = store.load()?;
    let mut api = DmmClient::new(&cli.api_base_url, session.map(|s| s.token))?;

    match &cli.command {
        Some(Commands::Login { code }) => {
            login(&mut api, &store, code.as_deref()).await?;
        }
        Some(Commands::Logout) => {
            let res = if api.token().is_some() { api.logout().await } else { Ok(()) };
            store.delete()?;
            res?;
            println!("Logged out.");
        }
        Some(Commands::Download) => {
            ensure_logged_in(&mut api, &store).await?;
            let manifest = install_manifest(&api).await?;
            fs::create_dir_all(&game_dir)?;
            let root = fs::canonicalize(&game_dir)?;
            if cli.dry_run {
                download::dry_run(manifest, root, cli.force, cli.jobs).await?;
            } else {
                download::download_all(api, manifest, root, cli.force, cli.jobs).await?;
            }
        }
        Some(Commands::Prepare) => {
            ensure_logged_in(&mut api, &store).await?;
            let manifest = install_manifest(&api).await?;
            fs::create_dir_all(&game_dir)?;
            let root = fs::canonicalize(&game_dir)?;
            download::download_all(api, manifest, root.clone(), cli.force, cli.jobs).await?;
            runtime::prepare(&root, &cli.runtime, bepinex.as_deref(), cli.force).await?;
        }
        Some(Commands::Launch) => {
            ensure_logged_in(&mut api, &store).await?;
            let root = fs::canonicalize(&game_dir)?;
            launch_game(&api, &store, &root, &cli.runtime, cli.dry_run).await?;
        }
        Some(Commands::Decrypt) => unreachable!(),
        None => {
            ensure_logged_in(&mut api, &store).await?;
            let manifest = install_manifest(&api).await?;
            fs::create_dir_all(&game_dir)?;
            let root = fs::canonicalize(&game_dir)?;
            download::download_all(api.clone(), manifest, root.clone(), cli.force, cli.jobs).await?;
            runtime::prepare(&root, &cli.runtime, bepinex.as_deref(), cli.force).await?;
            launch_game(&api, &store, &root, &cli.runtime, cli.dry_run).await?;
        }
    }
    Ok(())
}

async fn install_manifest(api: &DmmClient) -> Result<FileManifest, DynError> {
    let hardware = hardware::collect().await?;
    let info = api.install_info(PRODUCT_ID, GAME_TYPE, &hardware).await?;
    if let Some(version) = &info.latest_version {
        println!("Gakumas version: {version}");
    }
    if info.file_list_url.is_empty() {
        return Err("install API returned no file_list_url".into());
    }
    api.file_manifest(&info.file_list_url, info.sign.as_deref()).await
}

async fn ensure_logged_in(api: &mut DmmClient, store: &token::TokenStore) -> Result<(), DynError> {
    api.startup().await?;
    if let Some(token) = api.token() {
        if api.check_token(token).await.is_ok() {
            return Ok(());
        }
    }
    login(api, store, None).await
}

async fn login(
    api: &mut DmmClient,
    store: &token::TokenStore,
    code: Option<&str>,
) -> Result<(), DynError> {
    api.startup().await?;
    let input = match code {
        Some(code) => code.to_owned(),
        None => {
            let url = api.login_url().await?;
            eprintln!("Open this DMM login URL in your browser:\n{url}\nPaste callback URL or authorization code:");
            let mut browser = if cfg!(windows) {
                let mut cmd = std::process::Command::new("rundll32.exe");
                cmd.arg("url.dll,FileProtocolHandler");
                cmd
            } else {
                std::process::Command::new("xdg-open")
            };
            let _ = browser
                .arg(&url)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input
        }
    };
    let code = extract_code(&input)?;
    let token = api.issue_token(&code).await?;
    api.check_token(&token).await?;
    store.save(&StoredSession {
        token,
        stored_at: timestamp(),
    })?;
    println!("Login succeeded.");
    Ok(())
}

fn extract_code(input: &str) -> Result<String, DynError> {
    let input = input.trim();
    if input.is_empty() {
        return Err("no callback URL or authorization code supplied".into());
    }
    if let Ok(url) = url::Url::parse(input) {
        if let Some((_, code)) = url.query_pairs().find(|(k, v)| k == "code" && !v.is_empty()) {
            return Ok(code.into_owned());
        }
    }
    if let Some((_, rest)) = input.split_once("code=") {
        return Ok(rest.split(['&', '#']).next().unwrap_or(rest).to_string());
    }
    Ok(input.to_owned())
}

fn split_args(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for c in input.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

async fn launch_game(
    api: &DmmClient,
    store: &token::TokenStore,
    root: &Path,
    options: &runtime::Options,
    dry_run: bool,
) -> Result<(), DynError> {
    let hardware = hardware::collect().await?;
    let info = api.launch_info(PRODUCT_ID, GAME_TYPE, &hardware).await?;
    if let Some(token) = &info.access_token_info {
        store.save(&StoredSession {
            token: token.clone(),
            stored_at: timestamp(),
        })?;
    }
    let executable = root.join("gakumas.exe");
    if !dry_run && !executable.is_file() {
        return Err(format!("missing executable: {}", executable.display()).into());
    }
    let args = split_args(info.execute_args.as_deref().unwrap_or_default());
    if dry_run {
        println!("{} {}", executable.display(), args.join(" "));
        return Ok(());
    }
    let mut command = if cfg!(windows) {
        tokio::process::Command::new(&executable)
    } else {
        let mut cmd = tokio::process::Command::new(options.wine_bin());
        cmd.arg(&executable).env("WINEARCH", "win64");
        if let Some(prefix) = &options.wine_prefix {
            cmd.env("WINEPREFIX", std::path::absolute(prefix)?);
        }
        if root.join("winhttp.dll").is_file() {
            let mut overrides = std::env::var("WINEDLLOVERRIDES").unwrap_or_default();
            if !overrides.is_empty() {
                overrides.push(';');
            }
            overrides.push_str("winhttp=n,b");
            cmd.env("WINEDLLOVERRIDES", overrides);
        }
        cmd
    };
    let status = command.args(&args).current_dir(root).status().await?;
    if !status.success() {
        return Err(format!("game exited with {status}").into());
    }
    Ok(())
}

fn timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
