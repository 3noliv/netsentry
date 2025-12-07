#!/usr/bin/env bash
set -euo pipefail

echo "📦 Instalando sentry CLI..."

# Permitir sobreescribir el binario de Python si alguien quiere:
PYTHON_BIN="${PYTHON_BIN:-python3}"

if command -v pipx >/dev/null 2>&1; then
  echo "➡ Detectado pipx. Instalando con pipx..."
  pipx install . --force
else
  echo "ℹ️ pipx no encontrado. Instalando en el usuario (~/.local) con pip."
  "$PYTHON_BIN" -m pip install --user --upgrade pip
  "$PYTHON_BIN" -m pip install --user .
fi

echo ""
echo "✅ Instalación completada."

cat <<'EOF'
Si el comando "sentry" no se encuentra, añade ~/.local/bin a tu PATH, por ejemplo:

    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc   # o ~/.zshrc
    source ~/.bashrc   # o ~/.zshrc

Ahora puedes probar ejecutando:

    sentry --help

EOF
