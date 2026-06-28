mod updater;

use anyhow::{Context, Result};
use console::{style, Term};
use dialoguer::{Confirm, Input, Password, Select};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ---------- Сериализуемые данные для сохранения ----------
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SavedState {
    name: Option<String>,
    networks: Vec<SavedNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavedNetwork {
    ssid: String,
    password: String,
    role: String,
    remote_addr: Option<String>,
    virtual_ip: Option<String>,
}

impl SavedState {
    fn load() -> Self {
        let path = Self::file_path();
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                serde_json::from_str(&contents).unwrap_or_default()
            } else {
                Self::default()
            }
        } else {
            Self::default()
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn file_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("p2p-vpn")
            .join("config.json")
    }

    fn contains_ssid(&self, ssid: &str) -> bool {
        self.networks.iter().any(|n| n.ssid == ssid)
    }
}

// ---------- Служебные сообщения ----------
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ControlMessage {
    PeerAnnounce {
        user_name: String,
        network_name: String,
        role: Role,
        virtual_ip: String,
    },
    Ping {
        id: u64,
        virtual_ip: String,
    },
    Pong {
        id: u64,
        virtual_ip: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum Role {
    Creator,
    Client,
}

// ---------- Данные об участнике ----------
#[derive(Debug, Clone)]
struct PeerInfo {
    addr: SocketAddr,
    user_name: String,
    role: Role,
    last_seen: Instant,
    rtt: Option<Duration>,
}

// ---------- Состояние одной сети ----------
struct Network {
    name: String,
    owner: String,
    my_role: Role,
    my_virtual_ip: String,
    config: Arc<NetworkConfig>,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    shutdown_flag: Arc<AtomicBool>,
}

struct NetworkConfig {
    key: Arc<LessSafeKey>,
    subnet_ip: String,
    subnet_mask: u8,
    port: u16,
}

// ---------- Глобальное состояние ----------
struct AppState {
    name: Option<String>,
    networks: Vec<Arc<Mutex<Network>>>,
    saved: SavedState,
}

impl AppState {
    fn new(saved: SavedState) -> Self {
        Self {
            name: saved.name.clone(),
            networks: Vec::new(),
            saved,
        }
    }
}

// Утилиты
fn derive_key(ssid: &str, password: &str) -> [u8; 32] {
    let hash = digest(&SHA256, format!("{}:{}", ssid, password).as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_ref());
    key
}

fn encrypt_message(key: &LessSafeKey, plain: &[u8]) -> Vec<u8> {
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plain.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
        .unwrap();
    let mut result = Vec::with_capacity(12 + in_out.len() + 16);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);
    result.extend_from_slice(tag.as_ref());
    result
}

fn decrypt_message(key: &LessSafeKey, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let (nonce_bytes, rest) = data.split_at(12);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).ok()?;
    let mut in_out = rest.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut in_out).ok()?;
    Some(in_out.to_vec())
}

fn mask_to_string(mask: u8) -> String {
    let mut octets = [0u8; 4];
    for i in 0..mask {
        octets[(i / 8) as usize] |= 1 << (7 - (i % 8));
    }
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

// Синхронная работа сети в отдельном потоке
fn run_network_sync(net: Arc<Mutex<Network>>) {
    let (config, subnet_ip, my_name, network_name, my_role, shutdown_flag, peers) = {
        let net_guard = net.blocking_lock();
        (
            net_guard.config.clone(),
            net_guard.my_virtual_ip.clone(),
            net_guard.owner.clone(),
            net_guard.name.clone(),
            net_guard.my_role.clone(),
            net_guard.shutdown_flag.clone(),
            net_guard.peers.clone(),
        )
    };

    let mut tun_cfg = tun::Configuration::default();
    tun_cfg
        .address(&subnet_ip)
        .netmask(mask_to_string(config.subnet_mask))
        .mtu(1400)
        .up();
    #[cfg(target_os = "windows")]
    tun_cfg.platform_config(|cfg| cfg.wintun_file(true));

    let mut tun = tun::create(&tun_cfg).expect("Не удалось создать TUN-устройство");
    #[cfg(unix)]
    tun.set_nonblock().ok();

    let socket =
        UdpSocket::bind(("0.0.0.0", config.port)).expect("Не удалось привязать UDP сокет");
    socket.set_nonblocking(true).ok();

    let mut buf = vec![0u8; 2048];
    let mut ping_pending: HashMap<u64, (Instant, SocketAddr, String)> = HashMap::new();
    let mut last_hello = Instant::now();
    let mut name_suffix: u32 = 0;

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }

        if last_hello.elapsed() >= Duration::from_secs(2) {
            let announce = ControlMessage::PeerAnnounce {
                user_name: my_name.clone(),
                network_name: network_name.clone(),
                role: my_role.clone(),
                virtual_ip: subnet_ip.clone(),
            };
            let serialized = bincode::serialize(&announce).unwrap();
            let encrypted = encrypt_message(&config.key, &serialized);
            let peers_lock = peers.blocking_lock();
            for (_, info) in peers_lock.iter() {
                let _ = socket.send_to(&encrypted, info.addr);
            }
            last_hello = Instant::now();
        }

        // Чтение из TUN
        loop {
            match tun.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let packet = &buf[..n];
                    if packet.len() >= 20 {
                        let dst_ip = &packet[16..20];
                        let dst_str = format!("{}.{}.{}.{}", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
                        let peers = peers.blocking_lock();
                        if dst_str.ends_with(".255") || dst_str == "255.255.255.255" {
                            for (_, info) in peers.iter() {
                                let enc = encrypt_message(&config.key, packet);
                                let _ = socket.send_to(&enc, info.addr);
                            }
                        } else if let Some(info) = peers.get(&dst_str) {
                            let enc = encrypt_message(&config.key, packet);
                            let _ = socket.send_to(&enc, info.addr);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::error!("Ошибка чтения TUN: {}", e);
                    return;
                }
            }
        }

        // Чтение из UDP
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, src_addr)) => {
                    if n == 0 { continue; }
                    let data = &buf[..n];
                    if let Some(plain) = decrypt_message(&config.key, data) {
                        if let Ok(ctrl) = bincode::deserialize::<ControlMessage>(&plain) {
                            match ctrl {
                                ControlMessage::PeerAnnounce { user_name, virtual_ip, role, .. } => {
                                    let mut peers = peers.blocking_lock();
                                    let mut adjusted_name = user_name.clone();
                                    if peers.values().any(|p| p.user_name == adjusted_name) {
                                        name_suffix += 1;
                                        adjusted_name = format!("{}_{}", user_name, name_suffix);
                                    }
                                    peers.insert(virtual_ip.clone(), PeerInfo {
                                        addr: src_addr,
                                        user_name: adjusted_name,
                                        role,
                                        last_seen: Instant::now(),
                                        rtt: None,
                                    });
                                    let ping_id = rand::random();
                                    let ping_msg = ControlMessage::Ping { id: ping_id, virtual_ip: subnet_ip.clone() };
                                    let ping_enc = encrypt_message(&config.key, &bincode::serialize(&ping_msg).unwrap());
                                    let _ = socket.send_to(&ping_enc, src_addr);
                                    ping_pending.insert(ping_id, (Instant::now(), src_addr, virtual_ip));
                                }
                                ControlMessage::Ping { id, virtual_ip: _ } => {
                                    let pong = ControlMessage::Pong { id, virtual_ip: subnet_ip.clone() };
                                    let pong_enc = encrypt_message(&config.key, &bincode::serialize(&pong).unwrap());
                                    let _ = socket.send_to(&pong_enc, src_addr);
                                }
                                ControlMessage::Pong { id, virtual_ip: _ } => {
                                    if let Some((sent, _, peer_ip)) = ping_pending.remove(&id) {
                                        let rtt = sent.elapsed();
                                        let mut peers = peers.blocking_lock();
                                        if let Some(info) = peers.get_mut(&peer_ip) {
                                            info.rtt = Some(rtt);
                                        }
                                    }
                                }
                            }
                        } else if plain.len() >= 20 {
                            let src_ip = &plain[12..16];
                            let src_ip_str = format!("{}.{}.{}.{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
                            {
                                let mut peers = peers.blocking_lock();
                                peers.entry(src_ip_str.clone()).or_insert(PeerInfo {
                                    addr: src_addr,
                                    user_name: "unknown".into(),
                                    role: Role::Client,
                                    last_seen: Instant::now(),
                                    rtt: None,
                                });
                            }
                            if let Err(e) = tun.write_all(&plain) {
                                log::error!("Ошибка записи в TUN: {}", e);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::error!("Ошибка UDP: {}", e);
                    return;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------- Вспомогательные функции ввода ----------
async fn pause(term: &Term) -> Result<()> {
    Confirm::new()
        .with_prompt("Нажмите Enter")
        .default(true)
        .show_default(false)
        .wait_for_newline(true)
        .interact_on_opt(term)?;
    Ok(())
}

fn prompt_required(prompt: &str) -> Result<String> {
    loop {
        let s: String = Input::new().with_prompt(prompt).interact_text()?;
        if !s.trim().is_empty() {
            return Ok(s.trim().to_string());
        }
        println!("{}", style("Поле обязательно для заполнения.").red());
    }
}

fn prompt_password_required(prompt: &str) -> Result<String> {
    loop {
        let p = Password::new().with_prompt(prompt).interact()?;
        if !p.trim().is_empty() {
            return Ok(p);
        }
        println!("{}", style("Пароль не может быть пустым.").red());
    }
}

// ---------- Главное меню ----------
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    ctrlc::set_handler(|| std::process::exit(0))?;

    let term = Term::stdout();
    let (cols, rows) = term.size();
    if cols < 80 || rows < 25 {
        println!(
            "{}",
            style(format!(
                "Рекомендуется размер терминала не менее 80x25. Текущий размер: {}x{}",
                cols, rows
            ))
            .yellow()
        );
    }

    let os = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Unknown"
    };
    println!("Обнаружена ОС: {}", style(os).bold().green());
    println!();

    if let Err(e) = updater::check_for_updates(false) {
        eprintln!(
            "{}",
            style(format!("Не удалось проверить обновления: {e}")).yellow()
        );
    }

    let saved = SavedState::load();
    if let Some(ref name) = saved.name {
        println!("Загружено сохранённое имя: {}", style(name).cyan());
    }
    if !saved.networks.is_empty() {
        println!("Найдено сохранённых сетей: {}", saved.networks.len());
    }

    let state = Arc::new(Mutex::new(AppState::new(saved)));

    loop {
        term.clear_screen()?;
        println!("{}", style("=== P2P VPN Manager ===").bold().cyan());
        let state_guard = state.lock().await;
        let name_display = state_guard.name.as_deref().unwrap_or("не установлено");
        let has_active_networks = !state_guard.networks.is_empty();
        let has_saved_networks = !state_guard.saved.networks.is_empty();
        let mut items = vec![format!("Имя пользователя [{}]", style(name_display).yellow())];
        if has_saved_networks {
            items.push("Сохранённые сети".to_string());
        }
        if has_active_networks {
            items.push("Активные сети".to_string());
        }
        items.push("Подключиться к сети".to_string());
        items.push("Создать сеть".to_string());
        items.push("Обновить программу".to_string());
        drop(state_guard);

        let selection = Select::new()
            .with_prompt("Выберите действие")
            .items(&items)
            .default(0)
            .interact_on_opt(&term)?;
        let selection = match selection {
            Some(s) => s,
            None => break,
        };

        let mut idx = 0;
        if selection == idx {
            let new_name = prompt_required("Введите имя пользователя")?;
            let mut state_lock = state.lock().await;
            state_lock.name = Some(new_name.clone());
            state_lock.saved.name = Some(new_name);
            state_lock
                .saved
                .save()
                .unwrap_or_else(|e| eprintln!("Ошибка сохранения: {e}"));
            continue;
        }
        idx += 1;

        let has_saved = {
            let st = state.lock().await;
            !st.saved.networks.is_empty()
        };
        if has_saved {
            if selection == idx {
                let state_clone = state.clone();
                saved_networks_menu(&term, &state_clone).await?;
                continue;
            }
            idx += 1;
        }

        let has_active = {
            let st = state.lock().await;
            !st.networks.is_empty()
        };
        if has_active {
            if selection == idx {
                manage_active_networks(&term, &state).await?;
                continue;
            }
            idx += 1;
        }

        if selection == idx {
            connect_to_network(&term, &state).await?;
        } else if selection == idx + 1 {
            create_network(&term, &state).await?;
        } else if selection == idx + 2 {
            match updater::check_for_updates(true) {
                Ok(status) => {
                    println!("{}", style(format!("Обновление: {status}")).green());
                    if let self_update::Status::Updated(..) = status {
                        println!("Перезапустите программу для применения обновления.");
                        pause(&term).await?;
                        std::process::exit(0);
                    }
                }
                Err(e) => {
                    println!(
                        "{}",
                        style(format!("Ошибка обновления: {e:#}")).red()
                    );
                }
            }
            pause(&term).await?;
        }
    }

    let networks = {
        let state_lock = state.lock().await;
        state_lock.networks.clone()
    };
    for net in networks {
        let net = net.lock().await;
        net.shutdown_flag.store(true, Ordering::Relaxed);
    }
    let state_lock = state.lock().await;
    state_lock.saved.save()?;
    println!("Состояние сохранено. Выход.");
    Ok(())
}

async fn saved_networks_menu(term: &Term, state: &Arc<Mutex<AppState>>) -> Result<()> {
    loop {
        term.clear_screen()?;
        println!("{}", style("Сохранённые сети:").bold().cyan());
        let state_guard = state.lock().await;
        if state_guard.saved.networks.is_empty() {
            println!("Нет сохранённых сетей.");
            pause(term).await?;
            return Ok(());
        }
        let mut items: Vec<String> = state_guard
            .saved
            .networks
            .iter()
            .map(|n| {
                format!(
                    "{} ({}) IP: {}",
                    n.ssid,
                    n.role,
                    n.virtual_ip.as_deref().unwrap_or("-")
                )
            })
            .collect();
        items.push("Удалить сохранённую сеть".to_string());
        items.push("Назад".to_string());
        drop(state_guard);

        let selection = Select::new()
            .items(&items)
            .default(0)
            .interact_on_opt(term)?;
        let selection = match selection {
            Some(s) => s,
            None => return Ok(()),
        };

        let mut state_lock = state.lock().await;
        if selection < state_lock.saved.networks.len() {
            let net = state_lock.saved.networks[selection].clone();
            drop(state_lock);

            let ssid = net.ssid.clone();
            let password = net.password.clone();
            let role = net.role.clone();
            let remote_addr = net.remote_addr.clone();
            let virtual_ip = net.virtual_ip.clone();

            let state_clone = state.clone();
            if role == "creator" {
                create_network_from_saved(term, &state_clone, ssid, password, virtual_ip).await?;
            } else {
                let addr_str = remote_addr.unwrap_or_else(|| "127.0.0.1:51820".to_string());
                connect_to_network_from_saved(
                    term,
                    &state_clone,
                    ssid,
                    password,
                    addr_str,
                    virtual_ip,
                )
                .await?;
            }
            return Ok(());
        } else if selection == state_lock.saved.networks.len() {
            if state_lock.saved.networks.is_empty() {
                println!("Нет сетей для удаления.");
                pause(term).await?;
                continue;
            }
            let ssids: Vec<String> = state_lock
                .saved
                .networks
                .iter()
                .map(|n| n.ssid.clone())
                .collect();
            let delete_sel = Select::new()
                .with_prompt("Выберите сеть для удаления")
                .items(&ssids)
                .default(0)
                .interact_on_opt(term)?;
            if let Some(idx) = delete_sel {
                state_lock.saved.networks.remove(idx);
                state_lock.saved.save()?;
                println!("Сеть удалена.");
                pause(term).await?;
            }
        } else {
            return Ok(());
        }
    }
}

async fn create_network_from_saved(
    term: &Term,
    state: &Arc<Mutex<AppState>>,
    ssid: String,
    password: String,
    virtual_ip: Option<String>,
) -> Result<()> {
    let mut state_guard = state.lock().await;
    let user = match &state_guard.name {
        Some(n) => n.clone(),
        None => {
            println!("Сначала установите имя пользователя.");
            pause(term).await?;
            return Ok(());
        }
    };

    let is_new = virtual_ip.is_none();
    if is_new && state_guard.saved.contains_ssid(&ssid) {
        println!(
            "{}",
            style(format!("Сеть с именем '{}' уже существует.", ssid)).red()
        );
        pause(term).await?;
        return Ok(());
    }

    let subnet_ip = virtual_ip
        .clone()
        .unwrap_or_else(|| format!("10.0.0.{}", rand::random::<u8>() % 253 + 1));

    let config = Arc::new(NetworkConfig {
        key: Arc::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &derive_key(&ssid, &password))
                .map_err(|_| anyhow::anyhow!("Ошибка инициализации ключа шифрования"))?,
        )),
        subnet_ip: subnet_ip.clone(),
        subnet_mask: 24,
        port: 51820,
    });

    let peers = Arc::new(Mutex::new(HashMap::new()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let network = Arc::new(Mutex::new(Network {
        name: ssid.clone(),
        owner: user.clone(),
        my_role: Role::Creator,
        my_virtual_ip: subnet_ip.clone(),
        config,
        peers,
        shutdown_flag: shutdown.clone(),
    }));

    let net_clone = network.clone();
    std::thread::spawn(move || {
        run_network_sync(net_clone);
    });

    if is_new {
        state_guard.saved.networks.push(SavedNetwork {
            ssid: ssid.clone(),
            password,
            role: "creator".to_string(),
            remote_addr: None,
            virtual_ip: Some(subnet_ip.clone()),
        });
    } else {
        if let Some(saved_net) = state_guard
            .saved
            .networks
            .iter_mut()
            .find(|n| n.ssid == ssid && n.role == "creator")
        {
            saved_net.virtual_ip = Some(subnet_ip.clone());
        }
    }
    state_guard.saved.save()?;
    state_guard.networks.push(network);

    println!(
        "{}",
        style(format!(
            "Сеть '{}' создана пользователем '{}'. Ваш IP: {}",
            ssid, user, subnet_ip
        ))
        .green()
    );
    pause(term).await?;
    Ok(())
}

async fn connect_to_network_from_saved(
    term: &Term,
    state: &Arc<Mutex<AppState>>,
    ssid: String,
    password: String,
    remote_addr_str: String,
    virtual_ip: Option<String>,
) -> Result<()> {
    let remote_addr: SocketAddr = remote_addr_str
        .parse()
        .context("Неверный формат адреса в сохранении")?;

    let mut state_guard = state.lock().await;
    let is_new = virtual_ip.is_none();
    if is_new && state_guard.saved.contains_ssid(&ssid) {
        println!(
            "{}",
            style(format!("Сеть с именем '{}' уже существует.", ssid)).red()
        );
        pause(term).await?;
        return Ok(());
    }

    let subnet_ip = virtual_ip
        .clone()
        .unwrap_or_else(|| format!("10.0.0.{}", rand::random::<u8>() % 253 + 1));

    let config = Arc::new(NetworkConfig {
        key: Arc::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &derive_key(&ssid, &password))
                .map_err(|_| anyhow::anyhow!("Ошибка инициализации ключа шифрования"))?,
        )),
        subnet_ip: subnet_ip.clone(),
        subnet_mask: 24,
        port: 51820,
    });

    let peers = Arc::new(Mutex::new(HashMap::new()));
    peers.lock().await.insert(
        "unknown".to_string(),
        PeerInfo {
            addr: remote_addr,
            user_name: "?".into(),
            role: Role::Client,
            last_seen: Instant::now(),
            rtt: None,
        },
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let network = Arc::new(Mutex::new(Network {
        name: ssid.clone(),
        owner: String::new(),
        my_role: Role::Client,
        my_virtual_ip: subnet_ip.clone(),
        config,
        peers,
        shutdown_flag: shutdown.clone(),
    }));

    let net_clone = network.clone();
    std::thread::spawn(move || {
        run_network_sync(net_clone);
    });

    if is_new {
        state_guard.saved.networks.push(SavedNetwork {
            ssid: ssid.clone(),
            password,
            role: "client".to_string(),
            remote_addr: Some(remote_addr_str),
            virtual_ip: Some(subnet_ip.clone()),
        });
    } else {
        if let Some(saved_net) = state_guard
            .saved
            .networks
            .iter_mut()
            .find(|n| n.ssid == ssid && n.role == "client")
        {
            saved_net.virtual_ip = Some(subnet_ip.clone());
            saved_net.remote_addr = Some(remote_addr_str);
        }
    }
    state_guard.saved.save()?;
    state_guard.networks.push(network);

    println!(
        "{}",
        style(format!(
            "Подключение к '{}'... Ваш IP: {}",
            ssid, subnet_ip
        ))
        .green()
    );
    pause(term).await?;
    Ok(())
}

async fn connect_to_network(term: &Term, state: &Arc<Mutex<AppState>>) -> Result<()> {
    let state_guard = state.lock().await;
    if state_guard.name.is_none() {
        drop(state_guard);
        println!("{}", style("Сначала установите имя пользователя.").red());
        pause(term).await?;
        return Ok(());
    }
    drop(state_guard);

    let ssid = prompt_required("SSID существующей сети")?;
    let password = prompt_password_required("Пароль сети")?;
    let remote = prompt_required("IP:port хотя бы одного узла (например, 1.2.3.4:51820)")?;
    let remote_addr: SocketAddr = remote.parse().context("Неверный формат адреса")?;
    let subnet_ip = format!("10.0.0.{}", rand::random::<u8>() % 253 + 1);

    let mut state_guard = state.lock().await;
    if state_guard.saved.contains_ssid(&ssid) {
        println!(
            "{}",
            style(format!("Сеть с именем '{}' уже существует.", ssid)).red()
        );
        pause(term).await?;
        return Ok(());
    }

    let config = Arc::new(NetworkConfig {
        key: Arc::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &derive_key(&ssid, &password))
                .map_err(|_| anyhow::anyhow!("Ошибка инициализации ключа шифрования"))?,
        )),
        subnet_ip: subnet_ip.clone(),
        subnet_mask: 24,
        port: 51820,
    });

    let peers = Arc::new(Mutex::new(HashMap::new()));
    peers.lock().await.insert(
        "unknown".to_string(),
        PeerInfo {
            addr: remote_addr,
            user_name: "?".into(),
            role: Role::Client,
            last_seen: Instant::now(),
            rtt: None,
        },
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let network = Arc::new(Mutex::new(Network {
        name: ssid.clone(),
        owner: String::new(),
        my_role: Role::Client,
        my_virtual_ip: subnet_ip.clone(),
        config,
        peers,
        shutdown_flag: shutdown.clone(),
    }));

    let net_clone = network.clone();
    std::thread::spawn(move || {
        run_network_sync(net_clone);
    });

    state_guard.saved.networks.push(SavedNetwork {
        ssid: ssid.clone(),
        password,
        role: "client".to_string(),
        remote_addr: Some(remote),
        virtual_ip: Some(subnet_ip.clone()),
    });
    state_guard.saved.save()?;
    state_guard.networks.push(network);

    println!(
        "{}",
        style(format!(
            "Подключение к '{}'... Ваш IP: {}",
            ssid, subnet_ip
        ))
        .green()
    );
    pause(term).await?;
    Ok(())
}

async fn create_network(term: &Term, state: &Arc<Mutex<AppState>>) -> Result<()> {
    let state_guard = state.lock().await;
    if state_guard.name.is_none() {
        drop(state_guard);
        println!("{}", style("Сначала установите имя пользователя.").red());
        pause(term).await?;
        return Ok(());
    }
    let user = state_guard.name.clone().unwrap();
    drop(state_guard);

    let ssid = prompt_required("Имя сети (SSID)")?;
    let password = prompt_password_required("Пароль сети")?;
    let subnet_ip = format!("10.0.0.{}", rand::random::<u8>() % 253 + 1);

    let mut state_guard = state.lock().await;
    if state_guard.saved.contains_ssid(&ssid) {
        println!(
            "{}",
            style(format!("Сеть с именем '{}' уже существует.", ssid)).red()
        );
        pause(term).await?;
        return Ok(());
    }

    let config = Arc::new(NetworkConfig {
        key: Arc::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &derive_key(&ssid, &password))
                .map_err(|_| anyhow::anyhow!("Ошибка инициализации ключа шифрования"))?,
        )),
        subnet_ip: subnet_ip.clone(),
        subnet_mask: 24,
        port: 51820,
    });

    let peers = Arc::new(Mutex::new(HashMap::new()));

    let shutdown = Arc::new(AtomicBool::new(false));
    let network = Arc::new(Mutex::new(Network {
        name: ssid.clone(),
        owner: user.clone(),
        my_role: Role::Creator,
        my_virtual_ip: subnet_ip.clone(),
        config,
        peers,
        shutdown_flag: shutdown.clone(),
    }));

    let net_clone = network.clone();
    std::thread::spawn(move || {
        run_network_sync(net_clone);
    });

    state_guard.saved.networks.push(SavedNetwork {
        ssid: ssid.clone(),
        password,
        role: "creator".to_string(),
        remote_addr: None,
        virtual_ip: Some(subnet_ip.clone()),
    });
    state_guard.saved.save()?;
    state_guard.networks.push(network);

    println!(
        "{}",
        style(format!(
            "Сеть '{}' создана пользователем '{}'. Ваш IP: {}",
            ssid, user, subnet_ip
        ))
        .green()
    );
    pause(term).await?;
    Ok(())
}

async fn manage_active_networks(term: &Term, state: &Arc<Mutex<AppState>>) -> Result<()> {
    loop {
        term.clear_screen()?;
        let state_guard = state.lock().await;
        if state_guard.networks.is_empty() {
            drop(state_guard);
            println!("Нет активных сетей.");
            pause(term).await?;
            return Ok(());
        }
        println!("{}", style("Активные сети:").bold().cyan());
        let mut items = Vec::new();
        for net in &state_guard.networks {
            let net = net.lock().await;
            let peers = net.peers.lock().await;
            let owner = if net.my_role == Role::Creator {
                net.owner.clone()
            } else {
                peers
                    .iter()
                    .find(|(_, info)| info.role == Role::Creator)
                    .map(|(_, info)| info.user_name.clone())
                    .unwrap_or_else(|| "неизвестен".to_string())
            };
            let participants: Vec<String> = peers
                .iter()
                .filter(|(ip, _)| *ip != "unknown")
                .map(|(ip, info)| {
                    let ping = info
                        .rtt
                        .map(|d| format!("{}ms", d.as_millis()))
                        .unwrap_or_else(|| "?ms".to_string());
                    format!("{} ({}), пинг {}", info.user_name, ip, ping)
                })
                .collect();
            let info_line = format!(
                "Сеть: {}, владелец: {}, участники: [{}]",
                net.name,
                owner,
                participants.join(", ")
            );
            items.push(info_line);
        }
        items.push("Остановить сеть".to_string());
        items.push("Назад".to_string());

        let selection = Select::new()
            .with_prompt("Выберите сеть или действие")
            .items(&items)
            .default(0)
            .interact_on_opt(term)?;
        let selection = match selection {
            Some(s) => s,
            None => return Ok(()),
        };

        if selection < state_guard.networks.len() {
            pause(term).await?;
        } else if selection == state_guard.networks.len() {
            if let Some(net) = state_guard.networks.first() {
                let net = net.lock().await;
                net.shutdown_flag.store(true, Ordering::Relaxed);
                println!("Сеть {} остановлена.", net.name);
                drop(net);
                pause(term).await?;
            }
        } else {
            return Ok(());
        }
    }
}