use anyhow::{Context, Result};
use self_update::{
    backends::github::{ReleaseList, Update},
    cargo_crate_version, Status,
};

pub fn check_for_updates(do_update: bool) -> Result<Status> {
    let releases = ReleaseList::configure()
        .repo_owner("HardCockMaster")
        .repo_name("P2P-VPN")
        .build()
        .context("Не удалось настроить GitHub API")?
        .fetch()
        .context("Ошибка получения списка релизов")?;

    let current_version = cargo_crate_version!();
    let latest = releases.first().context("Релизы не найдены")?;

    // Приводим обе версии к строковому срезу для сравнения
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
        let status = Update::configure()
            .repo_owner("HardCockMaster")
            .repo_name("P2P-VPN")
            .bin_name("p2p-vpn")
            .current_version(cargo_crate_version!())
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