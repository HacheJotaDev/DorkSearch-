#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# Instalador automático para Termux (Android)
# Uso:  bash scripts/install_termux.sh
# Requisito: Termux instalado desde F-Droid (no desde Play Store).
# ============================================================
set -e

echo "== [1/4] Actualizando paquetes de Termux =="
pkg update -y && pkg upgrade -y

echo "== [2/4] Instalando Python y utilidades =="
pkg install -y python git nano

echo "== [3/4] Instalando dependencias Python del núcleo (SIN GUI) =="
pip install --upgrade pip
pip install -r requirements.txt

echo "== [4/4] Verificación rápida =="
python main.py --version
python main.py stats || true

echo
echo "============================================================"
echo " Instalación completada."
echo " Arranca el menú de consola con:"
echo "     python main.py menu"
echo
echo " Notas:"
echo "  - La GUI PySide6 NO está soportada en Android; el menú"
echo "    de consola tiene TODAS las funciones."
echo "  - Crea tu .env:  cp .env.example .env && nano .env"
echo "  - Edita proxies.txt (IP:PORT:USER:PASSWORD) si los vas a usar."
echo "============================================================"
