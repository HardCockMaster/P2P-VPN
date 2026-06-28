#!/usr/bin/env bash
set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}P2P VPN Installer${NC}"
echo "Определение ОС..."

OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS" != "Linux" && "$OS" != "Darwin" ]]; then
    echo -e "${RED}Ошибка: эта программа поддерживает только Linux и macOS.${NC}"
    exit 1
fi

# Проверка прав (для Linux нужно будет установить capability)
if [[ "$OS" == "Linux" && "$EUID" -ne 0 ]]; then
    echo -e "${YELLOW}Для установки capability потребуются права sudo.${NC}"
fi

# Определяем путь установки
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="$HOME/.config/p2p-vpn"

echo "Копирование исполняемого файла..."
if [[ -f "./p2p-vpn" ]]; then
    sudo cp ./p2p-vpn "$INSTALL_DIR/p2p-vpn"
    sudo chmod +x "$INSTALL_DIR/p2p-vpn"
else
    echo -e "${RED}Файл p2p-vpn не найден в текущей папке.${NC}"
    exit 1
fi

# Настройка capability для TUN (Linux)
if [[ "$OS" == "Linux" ]]; then
    echo "Настройка прав для создания TUN-интерфейсов..."
    sudo setcap cap_net_admin+eip "$INSTALL_DIR/p2p-vpn"
    echo -e "${GREEN}Права установлены. Программа будет работать без sudo.${NC}"
fi

# Создание конфигурационной папки
mkdir -p "$CONFIG_DIR"

echo -e "${GREEN}Установка завершена.${NC}"
echo "Программа установлена в $INSTALL_DIR/p2p-vpn"
echo "Конфигурация будет храниться в $CONFIG_DIR"
echo "Запустите 'p2p-vpn' в терминале."
