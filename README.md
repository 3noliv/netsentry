# NetSentry CLI

### Análisis de seguridad en redes domésticas y pequeñas LAN

---

NetSentry es una herramienta de línea de comandos diseñada para **detectar configuraciones inseguras**, **servicios expuestos** y **malas prácticas** en redes locales.

Pensada para usuarios sin conocimientos técnicos, pero con la potencia necesaria para entornos de formación y auditorías ligeras.

La herramienta genera automáticamente:

* 📄 **JSON** con todos los datos del escaneo
* 🌐 **Informe HTML** visual
* 📝 **Playbook Markdown** con hallazgos + recomendaciones

---

# Funcionalidades principales

### Escaneo de hosts o redes completas

```bash
sentry scan -H 192.168.1.1
sentry scan -n 192.168.1.0/24
```

### Detección de malas prácticas

Incluye comprobaciones para:

* HTTP sin TLS / login por HTTP
* HTTPS sin HSTS
* TLS 1.0/1.1
* Telnet / FTP / SMB en texto plano
* Servicios IoT expuestos
* UPnP / SSDP accesibles
* Fingerprinting de dispositivo (router, IoT, NAS…)

### Motor avanzado de reglas (rules.yaml)

Cada hallazgo se clasifica por:

* Severidad (**LOW**, **MEDIUM**, **HIGH**)
* Categoría: CIFRADO, AUTENTICACION, IOT, EXPOSICIÓN…
* Puntuación por host y del escaneo completo

### CLI avanzada

* `--verbose` / `--quiet`
* `--json-only`, `--no-html`, `--no-markdown`
* `--no-http`, `--no-plaintext`, `--no-iot`, `--only-http`
* `sentry summary` → resumen del último escaneo
* `sentry open-last` → abre el informe HTML
* `sentry find` → busca hallazgos en todos los resultados
* `sentry report` → genera informes desde un JSON previo

---

# Requisitos

* Python **3.10+** (recomendado 3.11 o superior)
* Windows, Linux o macOS
* Estar conectado a la red que se desea analizar

---

# ⚙️ Instalación (1 comando)

## 🔹 Linux / macOS

```bash
chmod +x install.sh
./install.sh
```

## 🔹 Windows (PowerShell)

```powershell
.\install.ps1
```

Tras la instalación, el comando queda disponible globalmente:

```bash
sentry --help
```

---

# Uso básico

### 🎯 Escanear un host

```bash
sentry scan -H 192.168.1.1
```

### 🌐 Escanear una red completa

```bash
sentry scan -n 192.168.1.0/24
```

### 📂 Resultados generados automáticamente en `out/`:

```
results_<id>.json
report_<id>.html
report_<id>.md
```

---

# 🔧 Opciones útiles

### Ver más detalles durante el escaneo

```bash
sentry scan -H 192.168.1.1 --verbose
```

### Solo JSON

```bash
sentry scan -H 192.168.1.1 --json-only
```

### Saltar comprobaciones

```bash
sentry scan -H 192.168.1.1 --no-http
sentry scan -H 192.168.1.1 --no-plaintext
sentry scan -H 192.168.1.1 --no-iot
```

### Solo checks web

```bash
sentry scan -H 192.168.1.1 --only-http
```

### Modo silencioso

```bash
sentry scan -H 192.168.1.1 --quiet
```

---

# 📝 Trabajo con informes

### Regenerar informes desde JSON

```bash
sentry report -i out/results_abcd1234.json
```

### Resumen del último escaneo

```bash
sentry summary
```

### Abrir el último HTML

```bash
sentry open-last
```

### Buscar hallazgos en todos los resultados

```bash
sentry find HIGH
sentry find SMB
sentry find HTTP_NO_TLS
```

---

# Interpretación rápida del informe

Cada host incluye:

* Nivel de riesgo: **LOW**, **MEDIUM**, **HIGH**
* Score total
* Categorías afectadas
* Lista de hallazgos con:

  * ID (p. ej. `HTTP_NO_TLS`)
  * Severidad
  * Puerto
  * Explicación clara
  * Recomendación práctica

---

# ⚙️ Configuración opcional (config.yaml)

Puedes personalizar parámetros opcionalmente:

```bash
cp examples/sample_config.yaml config.yaml
```

Ejemplo:

```yaml
scan:
  timeout_ms: 500
  default_ports: [22, 80, 443]

report:
  include_closed: false
```

---

# ⚠️ Uso responsable

NetSentry está diseñada para:

* redes domésticas
* laboratorios propios
* formación y concienciación

❗ **No utilices esta herramienta en redes que no te pertenezcan o sin autorización expresa.**

---

# 🛠️ Desarrollo / Estructura del proyecto

```text
netsentry/
├── cli.py           → CLI principal
├── checks/          → Comprobaciones HTTP, IoT, SMB…
├── rules/           → Motor de reglas + rules.yaml
├── report/          → Plantillas HTML/MD + exportadores
├── scan/            → Descubrimiento de puertos y servicios
├── models/          → Modelos Pydantic
install.sh           → Instalación en Linux/macOS
install.ps1          → Instalación en Windows
out/                 → Resultados generados por el usuario
```

---

# 🤝 Contribuir

Si encuentras errores o deseas mejorar NetSentry, ¡puedes hacerlo!
La herramienta es modular y permite añadir:

* nuevas reglas
* nuevos checks
* nuevos formatos de informe
