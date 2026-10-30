use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use russh::client::{self, Handle, Handler};
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
) -> Result<String, String> {
    let fp = Arc::new(StdMutex::new(String::new()));
    let handler = Client {
        fp: fp.clone(),
        known: known_fp.clone(),
        trust,
    };
    let config = Arc::new(client::Config::default());

    let connected = client::connect(config, (host.as_str(), port), handler).await;
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
async fn run(state: State<'_, AppState>, command: String) -> Result<RunOut, String> {
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
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![connect, disconnect, run, parse_yaml])
        .run(tauri::generate_context!())
        .expect("ошибка запуска приложения");
}
