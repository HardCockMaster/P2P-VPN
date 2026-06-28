# P2P VPN Installer for Windows
Write-Host "P2P VPN Installer" -ForegroundColor Green

$ErrorActionPreference = "Stop"

# Проверка архитектуры
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    Write-Host "Предупреждение: программа собрана для x86_64, возможна несовместимость." -ForegroundColor Yellow
}

# Путь установки
$installDir = "$env:LOCALAPPDATA\Programs\p2p-vpn"
$exePath = "$installDir\p2p-vpn.exe"

# Создаём директорию
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# Копируем бинарник
if (Test-Path ".\p2p-vpn.exe") {
    Copy-Item ".\p2p-vpn.exe" -Destination $exePath -Force
} else {
    Write-Host "Файл p2p-vpn.exe не найден в текущей папке." -ForegroundColor Red
    exit 1
}

# Добавляем в PATH пользователя
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "Путь добавлен в переменную PATH." -ForegroundColor Green
}

# Для работы TUN под Windows потребуется установить Wintun DLL.
Write-Host "Установка завершена." -ForegroundColor Green
Write-Host "Программа установлена в $exePath"
Write-Host "Важно: для работы виртуальной сети скачайте wintun.dll с https://www.wintun.net/ и поместите в $installDir"
Write-Host "Перезапустите терминал, затем введите 'p2p-vpn'."
