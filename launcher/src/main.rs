mod client;
mod download;
mod hardware;
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
use models::{FileManifest, LaunchInfo, StoredSession};
use serde::Serialize;

const DEFAULT_API_BASE_URL: &str = "https://apidgp-gameplayer.games.dmm.com";

#[derive(Debug, Parser)]
#[command(name = "gakumas-launcher", version, about = "Gakumas DMM downloader, profile decryptor, and launcher")]
struct Cli {
    #[arg(long, global = true, default_value = "game")]
    dir: PathBuf,
    #[arg(long, global = true)]
    product_id: Option<String>,
    #[arg(long, global = true, default_value = "GCL")]
    game_type: String,
    #[arg(long, global = true, env = "DMM_API_BASE_URL", default_value = DEFAULT_API_BASE_URL)]
    api_base_url: String,
    #[command(flatten)]
    runtime: runtime::Options,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Login {
        #[arg(long)]
        code: Option<String>,
    },
    Logout,
    Games {
        #[arg(long)]
        json: bool,
    },
    Manifest,
    Download {
        #[arg(long, default_value_t = 8, alias = "concurrency")]
        jobs: usize,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Decrypt,
    Prepare {
        #[arg(long, default_value_t = 8, alias = "concurrency")]
        jobs: usize,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        bepinex: Option<PathBuf>,
    },
    Launch {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Serialize)]
struct PublicFile {
    path: String,
    size: u64,
    hash: Option<String>,
    check_hash: bool,
}

#[derive(Serialize)]
struct PublicManifest {
    version: String,
    files: Vec<PublicFile>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        if error.to_string() == "canceled" {
            eprintln!("Canceled.");
            std::process::exit(130);
        }
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    let cli = Cli::parse();
    if let Commands::Decrypt = &cli.command {
        fs::create_dir_all(&cli.dir)?;
        let root = fs::canonicalize(&cli.dir)?;
        return runtime::decrypt(&root, &cli.runtime).await;
    }

    let product_id = match &cli.command {
        Commands::Manifest
        | Commands::Download { .. }
        | Commands::Prepare { .. }
        | Commands::Launch { .. } => Some(
            cli.product_id
                .as_deref()
                .filter(|id| !id.trim().is_empty())
                .ok_or("--product-id is required; run `gakumas-launcher games` to view product IDs")?,
        ),
        _ => None,
    };

    let store = token::TokenStore::new()?;
    let session = store.load()?;
    let mut api = DmmClient::new(&cli.api_base_url, session.map(|s| s.token))?;

    match &cli.command {
        Commands::Login { code } => login(&mut api, &store, code.as_deref()).await?,
        Commands::Logout => {
            let res = if api.token().is_some() { api.logout().await } else { Ok(()) };
            store.delete()?;
            res?;
            println!("Logged out.");
        }
        Commands::Games { json } => {
            ensure_session(&api).await?;
            let games = api.games().await?;
            if *json {
                println!("{}", serde_json::to_string(&games)?);
            } else {
                for game in games {
                    println!(
                        "{}\t{}\t{}\t{}",
                        game.product_id,
                        game.game_type,
                        game.game_os,
                        game.title.unwrap_or_default()
                    );
                }
            }
        }
        Commands::Manifest => {
            let (info, manifest) = install_manifest(&api, product_id.unwrap(), &cli.game_type).await?;
            let version = info
                .latest_version
                .filter(|v| !v.is_empty())
                .ok_or("install API returned no version")?;
            let mut files = manifest
                .files
                .into_iter()
                .map(|file| {
                    let rel = download::safe_path(Path::new(""), &file.local_path)?;
                    Ok(PublicFile {
                        path: rel.to_string_lossy().replace('\\', "/"),
                        size: file.size,
                        hash: file.hash,
                        check_hash: file.check_hash,
                    })
                })
                .collect::<Result<Vec<_>, DynError>>()?;
            files.sort_by(|a, b| a.path.cmp(&b.path));
            println!("{}", serde_json::to_string(&PublicManifest { version, files })?);
        }
        Commands::Download { jobs, force, dry_run } => {
            let (_, manifest) = install_manifest(&api, product_id.unwrap(), &cli.game_type).await?;
            fs::create_dir_all(&cli.dir)?;
            let root = fs::canonicalize(&cli.dir)?;
            runtime::restore_backups(&root)?;
            if *dry_run {
                download::dry_run(manifest, root, *force, *jobs).await?;
            } else {
                download::download_all(api, manifest, root, *force, *jobs).await?;
            }
        }
        Commands::Prepare { jobs, force, bepinex } => {
            let (_, manifest) = install_manifest(&api, product_id.unwrap(), &cli.game_type).await?;
            fs::create_dir_all(&cli.dir)?;
            let root = fs::canonicalize(&cli.dir)?;
            runtime::restore_backups(&root)?;
            download::download_all(api, manifest, root.clone(), *force, *jobs).await?;
            runtime::prepare(&root, &cli.runtime, bepinex.as_deref()).await?;
        }
        Commands::Launch { dry_run } => {
            let root = fs::canonicalize(&cli.dir)?;
            ensure_session(&api).await?;
            let hardware = hardware::collect().await?;
            let info = api.launch_info(product_id.unwrap(), &cli.game_type, &hardware).await?;
            if let Some(token) = &info.access_token_info {
                store.save(&StoredSession {
                    token: token.clone(),
                    stored_at: timestamp(),
                })?;
            }
            launch(&root, &cli.runtime, info, *dry_run).await?;
        }
        Commands::Decrypt => unreachable!(),
    }
    Ok(())
}

async fn install_manifest(
    api: &DmmClient,
    product_id: &str,
    game_type: &str,
) -> Result<(LaunchInfo, FileManifest), DynError> {
    ensure_session(api).await?;
    let hardware = hardware::collect().await?;
    let info = api.install_info(product_id, game_type, &hardware).await?;
    if info.file_list_url.is_empty() {
        return Err("install API returned no file_list_url".into());
    }
    let manifest = api.file_manifest(&info.file_list_url, info.sign.as_deref()).await?;
    Ok((info, manifest))
}

async fn ensure_session(api: &DmmClient) -> Result<(), DynError> {
    api.startup().await?;
    let token = api.token().ok_or("Not logged in. Run `gakumas-launcher login` first.")?;
    api.check_token(token).await
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

async fn launch(
    root: &Path,
    options: &runtime::Options,
    info: LaunchInfo,
    dry_run: bool,
) -> Result<(), DynError> {
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
        let mut cmd = tokio::process::Command::new(&options.wine);
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
