Write-Host "📦 Instalando sentry CLI globalmente (usando Python por defecto)..."

python -m pip install -U pip
python -m pip install .

Write-Host ""
Write-Host "✅ Instalación completada."
Write-Host "Ya puedes usar la herramienta ejecutando:"
Write-Host "    sentry --help"
Write-Host ""

