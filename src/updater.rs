use anyhow::{Context, Result};
use self_update::{
    backends::github::ReleaseList,
    cargo_crate_version, Status,
    update::Release,
};
use std::env;
use std::fs;
use std::io::{self};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use flate2::read::GzDecoder;
use tar::Archive;

fn last_check_file() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
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
            if elapsed < Duration::from_secs(86400) {
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

fn target_triple() -> &'static str {
    if cfg!(target_os = "linux") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else {
        "unknown"
    }
}

/// Получить URL архива для текущей платформы из списка ассетов
fn find_asset_url(releases: &[Release]) -> Option<String> {
    let suffix = if cfg!(target_os = "windows") { "zip" } else { "tar.gz" };
    let expected_name = format!("p2p-vpn-{}.{}", target_triple(), suffix);

    for release in releases {
        for asset in &release.assets {
            if asset.name == expected_name {
                return Some(asset.download_url.clone());
            }
        }
    }
    None
}

/// Скачать и установить обновление вручную
fn manual_update(download_url: &str) -> Result<()> {
    let current_exe = std::env::current_exe()?;
    let tmp_dir = tempfile::tempdir()?;
    let archive_path = tmp_dir.path().join("update_archive");

    // Скачивание
    let response = ureq::get(download_url)
        .call()
        .context("Ошибка скачивания архива")?;
    let mut dest = fs::File::create(&archive_path)?;
    let mut reader = response.into_reader();
    io::copy(&mut reader, &mut dest)?;

    // Распаковка
    let file = fs::File::open(&archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let bin_name = if cfg!(target_os = "windows") { "p2p-vpn.exe" } else { "p2p-vpn" };

    let mut found = false;
    let new_bin_path = tmp_dir.path().join(bin_name);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.file_name().map(|n| n == bin_name).unwrap_or(false) {
            let mut outfile = fs::File::create(&new_bin_path)?;
            io::copy(&mut entry, &mut outfile)?;
            found = true;
            break;
        }
    }

    if !found {
        return Err(anyhow::anyhow!(
            "В архиве не найден исполняемый файл '{}'",
            bin_name
        ));
    }

    // Установка прав
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&new_bin_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&new_bin_path, perms)?;
    }

    // Замена текущего исполняемого файла
    let backup_path = current_exe.with_extension("old");
    let _ = fs::remove_file(&backup_path);
    fs::rename(&current_exe, &backup_path)?;
    fs::rename(&new_bin_path, &current_exe)?;
    let _ = fs::remove_file(&backup_path);

    Ok(())
}

pub fn check_for_updates(do_update: bool) -> Result<Status> {
    if !should_check() && !do_update {
        return Ok(Status::UpToDate("не проверено (кэш)".into()));
    }

    let token = env::var("GITHUB_TOKEN").ok();

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
        Err(e) => return Err(e).context("Не удалось настроить GitHub API"),
    };

    touch_check_file();

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
        let download_url = find_asset_url(&releases)
            .context("Не удалось найти подходящий архив в релизе")?;
        println!("Загрузка и установка обновления...");
        manual_update(&download_url)?;
        println!("Обновление успешно установлено. Перезапустите программу.");
        Ok(Status::Updated(format!("v{}", latest.version)))
    } else {
        Ok(Status::UpToDate(format!(
            "ожидание (новая: v{})",
            latest.version
        )))
    }
}