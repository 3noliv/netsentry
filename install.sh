#!/usr/bin/env bash
set -e

echo "📦 Instalando sentry CLI globalmente (usando Python por defecto)..."

python -m pip install -U pip
python -m pip install .

echo ""
echo "✅ Instalación completada."
echo "Ya puedes usar la herramienta ejecutando:"
echo "    sentry --help"
echo ""

