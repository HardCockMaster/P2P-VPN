use anyhow::{Context, Result};
use self_update::{
    backends::github::{ReleaseList, Update},
    cargo_crate_version, Status,
};
use std::time::{SystemTime, Duration};
use std::fs;
use std::path::PathBuf;

fn last_check_file() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
        .join("p2p-vpn")
        .join(".last_update_check")
}

fn should_check() -> bool {
    let path = last_check_file();
    if !path.exists() {
        return true;
    }
    if let Ok(metadata) = fs::metadata(&path) {
        if let Ok(modified) = metadata.modified() {
            let elapsed = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::from_secs(0));
            if elapsed < Duration::from_secs(86400) {  // сутки
                return false;
            }
        }
    }
    true
}

fn touch_check_file() {
    let path = last_check_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&path, "").ok();
}

pub fn check_for_updates(do_update: bool) -> Result<Status> {
    if !should_check() && !do_update {
        // Не проверяем, если нет принудительного обновления (из меню)
        return Ok(Status::UpToDate("не проверено (кэш)".into()));
    }

    let token = std::env::var("GITHUB_TOKEN").ok();

    let mut release_builder = ReleaseList::configure();
    release_builder.repo_owner("HardCockMaster").repo_name("P2P-VPN");
    if let Some(ref t) = token {
        release_builder.auth_token(t);
    }

    let releases = match release_builder.build() {
        Ok(built) => match built.fetch() {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("403") || msg.contains("rate limit") {
                    println!("⚠️  Слишком много запросов к GitHub. Проверка пропущена.");
                    return Ok(Status::UpToDate("неизвестно (лимит)".into()));
                } else {
                    return Err(e).context("Ошибка получения списка релизов");
                }
            }
        },
        Err(e) => {
            return Err(e).context("Не удалось настроить GitHub API");
        }
    };

    touch_check_file();  // успешный запрос — обновляем метку времени

    let current_version = cargo_crate_version!();
    let latest = match releases.first() {
        Some(l) => l,
        None => {
            println!("Релизы не найдены");
            return Ok(Status::UpToDate("неизвестно".into()));
        }
    };

    if latest.version.as_str() <= current_version {
        println!("Обновлений нет. Текущая версия: v{current_version}");
        return Ok(Status::UpToDate(format!("v{current_version}")));
    }

    println!(
        "Доступна новая версия: v{} (текущая: v{current_version})",
        latest.version
    );

    if do_update {
        println!("Загрузка и установка обновления...");
        let mut update_builder = Update::configure();
        update_builder
            .repo_owner("HardCockMaster")
            .repo_name("P2P-VPN")
            .bin_name("p2p-vpn")
            .current_version(cargo_crate_version!());
        if let Some(ref t) = token {
            update_builder.auth_token(t);
        }
        let status = update_builder
            .build()
            .context("Ошибка настройки обновления")?
            .update()
            .context("Не удалось установить обновление")?;
        println!("Обновление установлено. Перезапустите программу для применения новой версии.");
        Ok(status)
    } else {
        Ok(Status::UpToDate(format!(
            "ожидание (новая: v{})",
            latest.version
        )))
    }
}