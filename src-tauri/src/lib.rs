use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use russh::client::{self, Handle, Handler};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use russh::{ChannelMsg, Disconnect};
use russh_keys::key::PublicKey;
use serde::Serialize;
use tauri::State;
use tokio::sync::Mutex;

struct Client {
    fp: Arc<StdMutex<String>>,
    known: Option<String>,
    trust: bool,
}

#[async_trait::async_trait]
impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let fp = key.fingerprint();
        *self.fp.lock().unwrap() = fp.clone();
        Ok(self.trust || self.known.as_deref() == Some(fp.as_str()))
    }
}

#[derive(Default)]
struct AppState {
    session: Mutex<Option<Handle<Client>>>,
}

#[derive(Serialize)]
struct RunOut {
    output: String,
    code: Option<u32>,
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}


/// Находит адрес сервера. IP-адрес используется как есть. Для домена: если указан
/// свой DNS, спрашиваем его, иначе системный DNS устройства.
async fn resolve(host: &str, port: u16, dns: Option<&str>) -> Result<SocketAddr, String> {
    let h = host.trim().trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(d) = dns.map(str::trim).filter(|d| !d.is_empty()) {
        let ns: IpAddr = d
            .trim_matches(|c| c == '[' || c == ']')
            .parse()
            .map_err(|_| format!("DNS-сервер «{}» не похож на IP-адрес", d))?;
        let cfg = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[ns], 53, true),
        );
        let resolver = TokioAsyncResolver::tokio(cfg, ResolverOpts::default());
        let ips = resolver
            .lookup_ip(h)
            .await
            .map_err(|e| format!("DNS {} не нашёл «{}»: {}", ns, h, e))?;
        let ip = ips
            .iter()
            .next()
            .ok_or_else(|| format!("DNS {} не вернул адрес для «{}»", ns, h))?;
        return Ok(SocketAddr::new(ip, port));
    }
    let mut found = tokio::net::lookup_host((h, port))
        .await
        .map_err(|e| format!("Не удалось найти адрес «{}»: {}", h, e))?;
    found
        .next()
        .ok_or_else(|| format!("Для «{}» не найдено ни одного адреса", h))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn connect(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    user: String,
    password: String,
    key_path: Option<String>,
    known_fp: Option<String>,
    trust: bool,
    dns: Option<String>,
) -> Result<String, String> {
    let fp = Arc::new(StdMutex::new(String::new()));
    let handler = Client {
        fp: fp.clone(),
        known: known_fp.clone(),
        trust,
    };
    let config = Arc::new(client::Config::default());

    let addr = resolve(&host, port, dns.as_deref()).await?;
    let connected = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(config, addr, handler),
    )
    .await
    .map_err(|_| "Время ожидания подключения истекло (10 с)".to_string())?;
    let mut handle = match connected {
        Ok(h) => h,
        Err(e) => {
            let seen = fp.lock().unwrap().clone();
            if !seen.is_empty() && !trust {
                let kind = if known_fp.is_some() { "CHANGED" } else { "NEW" };
                return Err(format!("KEY:{}:{}", kind, seen));
            }
            return Err(format!("Не удалось подключиться: {}", e));
        }
    };

    let ok = match key_path.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(path) => {
            let pass = if password.is_empty() { None } else { Some(password.as_str()) };
            let key = russh_keys::load_secret_key(path, pass).map_err(err)?;
            handle
                .authenticate_publickey(&user, Arc::new(key))
                .await
                .map_err(err)?
        }
        None => handle
            .authenticate_password(&user, &password)
            .await
            .map_err(err)?,
    };
    if !ok {
        return Err("Неверный логин, пароль или ключ".into());
    }

    let fingerprint = fp.lock().unwrap().clone();
    *state.session.lock().await = Some(handle);
    Ok(fingerprint)
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(h) = state.session.lock().await.take() {
        let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    Ok(())
}

#[tauri::command]
async fn run_command(state: State<'_, AppState>, command: String) -> Result<RunOut, String> {
    let mut guard = state.session.lock().await;
    let handle = guard.as_mut().ok_or("Нет подключения")?;

    let work = async {
        let mut ch = handle.channel_open_session().await.map_err(err)?;
        ch.exec(true, command.as_bytes()).await.map_err(err)?;
        let mut out: Vec<u8> = Vec::new();
        let mut code = None;
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => out.extend_from_slice(data),
                ChannelMsg::ExtendedData { ref data, .. } => out.extend_from_slice(data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }
        Ok::<RunOut, String>(RunOut {
            output: String::from_utf8_lossy(&out).into_owned(),
            code,
        })
    };

    tokio::time::timeout(Duration::from_secs(120), work)
        .await
        .map_err(|_| "Команда выполняется дольше 120 секунд".to_string())?
}

#[tauri::command]
fn parse_yaml(text: String) -> Result<serde_json::Value, String> {
    serde_yaml::from_str::<serde_json::Value>(&text).map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![connect, disconnect, run_command, parse_yaml])
        .run(tauri::generate_context!())
        .expect("ошибка запуска приложения");
}
