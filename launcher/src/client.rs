use reqwest::{
    Client, Response,
    header::{HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use url::Url;

use crate::models::{AccessTokenInfo, FileEntry, FileManifest, HardwareInfo, LaunchInfo};

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct DmmClient {
    http: Client,
    base_url: Url,
    token: Option<AccessTokenInfo>,
}

impl DmmClient {
    pub fn new(base_url: &str, token: Option<AccessTokenInfo>) -> Result<Self, DynError> {
        let base_url = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))?;
        let http = Client::builder()
            .user_agent("DMMGamePlayer5-Win/5.5.19")
            .build()?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    pub fn token(&self) -> Option<&AccessTokenInfo> {
        self.token.as_ref()
    }

    pub async fn startup(&self) -> Result<(), DynError> {
        self.post("v5/startup", None, false).await.map(|_| ())
    }

    pub async fn login_url(&self) -> Result<String, DynError> {
        let data = self
            .post("v5/auth/login/url", Some(json!({"prompt":"choose"})), false)
            .await?;
        required_string(&data, &["url"])
    }

    pub async fn issue_token(&mut self, code: &str) -> Result<AccessTokenInfo, DynError> {
        let data = self
            .post(
                "v5/auth/accesstoken/issue",
                Some(json!({"code": code})),
                false,
            )
            .await?;
        let token = AccessTokenInfo {
            access_token: required_string(&data, &["access_token"])?,
            expires_in_seconds: required_i64(&data, &["expires_in_seconds"])?,
        };
        self.token = Some(token.clone());
        Ok(token)
    }

    pub async fn check_token(&self, token: &AccessTokenInfo) -> Result<(), DynError> {
        let data = self
            .post(
                "v5/auth/accesstoken/check",
                Some(serde_json::to_value(token)?),
                false,
            )
            .await?;
        if data.get("result").and_then(Value::as_bool) == Some(false) {
            return Err("DMM access token was rejected".into());
        }
        Ok(())
    }


    pub async fn install_info(
        &self,
        product_id: &str,
        game_type: &str,
        hardware: &HardwareInfo,
    ) -> Result<LaunchInfo, DynError> {
        self.game_info("v5/r2/install/cl", product_id, game_type, hardware)
            .await
    }

    pub async fn launch_info(
        &self,
        product_id: &str,
        game_type: &str,
        hardware: &HardwareInfo,
    ) -> Result<LaunchInfo, DynError> {
        self.game_info("v5/r2/launch/cl", product_id, game_type, hardware)
            .await
    }

    async fn game_info(
        &self,
        path: &str,
        product_id: &str,
        game_type: &str,
        hardware: &HardwareInfo,
    ) -> Result<LaunchInfo, DynError> {
        let mut body = json!({
            "product_id": product_id, "game_type": game_type, "game_os": "win",
            "mac_address": hardware.mac_address, "hdd_serial": hardware.hdd_serial,
            "motherboard": hardware.motherboard, "user_os": hardware.user_os
        });
        if path.ends_with("launch/cl") {
            body["launch_type"] = json!("LIB");
        }
        let data = self.post(path, Some(body), true).await?;
        parse_launch_info(&data, product_id)
    }

    pub async fn file_manifest(
        &self,
        file_list_url: &str,
        signed_cookie: Option<&str>,
    ) -> Result<FileManifest, DynError> {
        let url = self.base_url.join(file_list_url)?;
        let response = self.get_response(url, signed_cookie, false).await?;
        let root: Value = response.json().await?;
        let data = root.get("data").unwrap_or(&root);
        let domain = normalize_domain(
            data.get("domain")
                .and_then(Value::as_str)
                .unwrap_or_else(|| self.base_url.as_str()),
        )?;
        let list = data
            .get("file_list")
            .or_else(|| data.get("fileList"))
            .and_then(Value::as_array)
            .ok_or("DMM file manifest has no file_list")?;
        let files = list
            .iter()
            .map(|item| {
                Ok(FileEntry {
                    local_path: required_string(item, &["local_path", "localPath"] )?,
                    remote_path: required_string(item, &["path", "url"] )?,
                    size: integer(item, &["size", "file_size"]),
                    hash: optional_string(item, &["hash"]),
                    check_hash: boolean(item, &["check_hash_flg", "checkHashFlg"]),
                })
            })
            .collect::<Result<Vec<_>, DynError>>()?;
        Ok(FileManifest {
            domain,
            files,
            signed_cookie: signed_cookie.map(str::to_owned),
        })
    }

    pub async fn download_response(
        &self,
        domain: &str,
        path: &str,
        signed_cookie: Option<&str>,
    ) -> Result<Response, DynError> {
        let url = if let Ok(url) = Url::parse(path) {
            url
        } else {
            Url::parse(&format!("{}/", normalize_domain(domain)?))?
                .join(path.trim_start_matches('/'))?
        };
        self.get_response(url, signed_cookie, true).await
    }

    async fn get_response(
        &self,
        url: Url,
        signed_cookie: Option<&str>,
        assist: bool,
    ) -> Result<Response, DynError> {
        let mut headers = self.auth_headers(true, false)?;
        if assist {
            headers.insert("clientdll", HeaderValue::from_static("DGP5DLL"));
        }
        if let Some(cookie) = signed_cookie {
            headers.insert("cookie", HeaderValue::from_str(cookie)?);
        }
        let response = self.http.get(url).headers(headers).send().await?;
        if !response.status().is_success() {
            return Err(format!("DMM download request failed ({})", response.status()).into());
        }
        Ok(response)
    }

    pub async fn logout(&mut self) -> Result<(), DynError> {
        self.post("v5/auth/logout", None, true).await?;
        self.token = None;
        Ok(())
    }

    async fn post(
        &self,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Result<Value, DynError> {
        let headers = self.auth_headers(authenticated, true)?;
        let url = self.base_url.join(path)?;
        let request = self.http.post(url).headers(headers);
        let response = match body {
            Some(body) => request.json(&body).send().await?,
            None => request.send().await?,
        };
        let status = response.status();
        let body = response.bytes().await?;
        let root: Value = serde_json::from_slice(&body)
            .map_err(|_| format!("DMM API returned invalid JSON ({status}) for {path}"))?;
        if !status.is_success() {
            return Err(format!("DMM API request failed ({status}) for {path}").into());
        }
        if let Some(code) = root
            .get("result_code")
            .or_else(|| root.get("resultCode"))
            .and_then(Value::as_i64)
        {
            if code != 100 {
                return Err(format!("DMM API error {code} for {path}").into());
            }
        }
        Ok(root.get("data").cloned().unwrap_or(root))
    }

    fn auth_headers(&self, authenticated: bool, age_cookie: bool) -> Result<HeaderMap, DynError> {
        let mut headers = HeaderMap::new();
        headers.insert("client-app", HeaderValue::from_static("DMMGamePlayer5"));
        headers.insert("client-version", HeaderValue::from_static("5.5.19"));
        if authenticated {
            let token = self
                .token
                .as_ref()
                .ok_or("Not logged in. Run `gakumas-launcher login` first.")?;
            headers.insert("actauth", HeaderValue::from_str(&token.access_token)?);
            if age_cookie {
                headers.insert("cookie", HeaderValue::from_static("age_check_done=1"));
            }
        }
        Ok(headers)
    }
}


pub fn required_string(value: &Value, names: &[&str]) -> Result<String, DynError> {
    optional_string(value, names)
        .ok_or_else(|| format!("DMM response is missing {}", names[0]).into())
}
fn required_i64(value: &Value, names: &[&str]) -> Result<i64, DynError> {
    value
        .get(names[0])
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("DMM response is missing {}", names[0]).into())
}
fn optional_string(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str).map(str::to_owned))
}
fn integer(value: &Value, names: &[&str]) -> u64 {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_u64))
        .unwrap_or(0)
}
fn boolean(value: &Value, names: &[&str]) -> bool {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn parse_launch_info(data: &Value, _fallback: &str) -> Result<LaunchInfo, DynError> {
    Ok(LaunchInfo {
        file_list_url: optional_string(data, &["file_list_url", "fileListUrl"]).unwrap_or_default(),
        latest_version: optional_string(data, &["latest_version", "latestVersion"]),
        execute_args: optional_string(data, &["execute_args", "executeArgs"]),
        sign: optional_string(data, &["sign"]),
        access_token_info: data
            .get("access_token_info")
            .or_else(|| data.get("accessTokenInfo"))
            .and_then(|v| serde_json::from_value(v.clone()).ok()),
    })
}
fn normalize_domain(value: &str) -> Result<String, DynError> {
    if value.starts_with("http://") || value.starts_with("https://") {
        Ok(value.trim_end_matches('/').to_owned())
    } else {
        Ok(format!("https://{}", value.trim_matches('/')))
    }
}
