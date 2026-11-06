# 😎 URLS GOOGLE DORKS SEARCHER 🌟 — Advanced URL Discovery & SQLi Security Auditor

Herramienta profesional de OSINT y auditoría de seguridad en Python para
**descubrir miles o millones de URLs con Google Dorks**, priorizar las que
presentan superficie de consulta a base de datos y **auditar inyección SQL de
forma 100% NO destructiva** sobre objetivos autorizados — con proxies
residenciales rotativos, GUI completa, almacenamiento SQLite y exportación
TXT/CSV/JSON.

> ## ⚠️ USO RESPONSABLE (léelo)
> - **SOLO** para auditorías de seguridad con **autorización expresa** del
>   propietario del sistema (pentesting contractual, tu propia infraestructura,
>   laboratorios locales).
> - El motor de búsqueda exige una **lista blanca de dominios autorizados**.
> - El módulo SQLi es **no destructivo**: firmas de error y comparación
>   booleana (1=1 vs 1=2). **NO** extrae datos, **NO** enumera credenciales,
>   **NO** evada WAFs, **NO** ejecuta consultas apiladas y **NO** ataca sitios
>   públicos sin permiso.
> - Los proxies existen **únicamente para respetar los límites de tasa** del
>   servicio de búsqueda autorizado. Su uso para evadir CAPTCHAs o bloqueos
>   está prohibido.
> - La presencia de parámetros en una URL **NO** implica que exista inyección
>   SQL: los hallazgos solo provienen del módulo de auditoría.

---

## 1. Características

| Módulo | Qué hace |
|---|---|
| 🔍 **Motor de dorks** | Operadores `site:`, `inurl:`, `intitle:`, `filetype:`, `intext:`, exclusiones, presets y matrices combinadas. APIs autorizadas (Google CSE / SerpAPI), paginación por cola asyncio, deduplicación, filtros, cuota diaria, rate limit y backoff exponencial. |
| 🌐 **Proxies residenciales rotativos** | Formato `IP:PORT:USER:PASSWORD` en `proxies.txt`, autenticación, rotación round-robin/random/least-used, verificación asíncrona, estadísticas por proxy y expulsión temporal de los que fallan. Credenciales nunca en logs. |
| 🧭 **Analizador de parámetros** | Detecta parámetros GET relacionados con BD (`id`, `item`, `product`, `category`, `search`…), rutas dinámicas y prioriza la revisión (0–100). Estadísticas agregadas. |
| 🛡️ **Auditoría SQLi** | Lista blanca verificada ANTES de cada petición, detección por errores y booleana, control anti-falsos-positivos, verificación de reproducibilidad, niveles de evidencia (CONFIRMED/LIKELY/POSSIBLE/INFO), remediación con consultas parametrizadas y registro completo para reproducibilidad. |
| 🖥️ **GUI PySide6** | Panel de estadísticas, editor de dorks, gestor de proxies, tabla de URLs con filtros, panel de auditoría SQLi, barra de progreso, botones Iniciar/Pausar/Reanudar/Detener, registro en vivo y exportación. Nunca bloquea la interfaz (QThread + asyncio). |
| 💾 **Almacenamiento y export** | SQLite con índice de deduplicación, checkpoints de reanudación por dork, cuota por fecha, audit log y hallazgos. Exporta TXT/CSV/JSON en streaming (m millones de filas sin cargar en memoria). |
| 🧪 **Laboratorio SQLi local** | Servidor HTTP en `127.0.0.1` con datos ficticios: endpoints vulnerables (concatenación) y corregidos (parametrizados) para demostrar la detección y validar la reparación. |
| ✅ **Calidad** | Python 3.10+/3.12, httpx asíncrono, PySide6, pytest (unitarios + integración), credenciales por variables de entorno, compatible Windows/Linux. |

---

## 2. Instalación

Requisitos: **Python 3.10 o superior** (recomendado 3.12).

### Windows
```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

> En Linux, si la GUI queja de librerías Qt: `sudo apt install libegl1 libgl1 libxkbcommon0 libdbus-1-3 libfontconfig1`

### Credenciales de la API de búsqueda (una sola vez)
1. Entra en <https://console.cloud.google.com> → crea un proyecto → habilita **Custom Search API** → crea una **API Key**.
2. En <https://programmablesearchengine.google.com> crea un motor de búsqueda y copia el **Search engine ID (cx)**.
3. Edita `.env`:
   ```
   GOOGLE_API_KEY=tu_clave
   GOOGLE_CSE_ID=tu_cx
   ```
   (Alternativa comercial: define `SERPAPI_KEY` y usa el proveedor `serpapi`.)

Las credenciales NUNCA van en el código: solo en `.env` / variables de entorno.

---

## 3. Configuración

- **`config.example.json`** → cópialo a `config.json` y ajústalo. Secciones:
  - `search`: proveedor, resultados por página, máximos, cuota diaria, concurrencia, rate limit, backoff y **lista blanca autorizada**.
  - `proxies`: fichero, estrategia, expulsión tras N fallos, TTL.
  - `sqli`: dominios autorizados, técnicas, timeout, límites de peticiones.
  - `storage` / `export`: rutas y tamaños de lote.
- **`proxies.txt`** → un proxy por línea en formato:
  ```
  IP:PORT:USER:PASSWORD
  ```
  (la contraseña puede contener `:`; las líneas `#` son comentarios).

---

## 4. Uso — GUI (recomendado)

```bash
python main.py gui
```

- **Panel**: estadísticas globales + botón de análisis/priorización de parámetros.
- **Búsqueda (Dorks)**: editor de dorks, presets, lista blanca, opciones del motor y botones **Iniciar / Pausar / Reanudar / Detener**. Las URLs aparecen en vivo y todo corre en segundo plano.
- **URLs**: tabla con filtros (dominio, extensión, prioridad mínima, con parámetros) y exportación TXT/CSV/JSON.
- **Proxies**: carga `proxies.txt`, estrategia de rotación, verificación asíncrona y estadísticas (credenciales ocultas).
- **Auditoría SQLi**: lista blanca + URL objetivo + técnicas; incluye botón **“Iniciar laboratorio local”** y **“Generar informe”** (JSON + Markdown en `reports/`).

## 5. Uso — CLI

```bash
# Buscar URLs (motor completo, reanudable, con export)
python main.py --config config.json search \
    --domain ejemplo-autorizado.com \
    --preset php_id --preset paneles_admin \
    --out exports/urls.json

# Ver presets disponibles
python main.py search --list-presets

# Dorks literales o desde fichero (un dork por línea)
python main.py search --domain ejemplo.com --dork 'site:ejemplo.com inurl:product.php?id='
python main.py search --domain ejemplo.com --dorks-file dorks.txt

# Con rotación de proxies (solo para respetar rate limits)
python main.py search --domain ejemplo.com --preset php_id --use-proxies

# Priorizar parámetros de las URLs almacenadas
python main.py analyze

# Auditoría SQLi NO destructiva de una URL autorizada
python main.py audit --url "http://lab.ejemplo.com/producto.php?id=1" --domain lab.ejemplo.com

# Laboratorio local interactivo
python main.py lab --port 8000

# Demo completa en local (laboratorio + auditoría + informe de ejemplo)
python main.py lab-demo

# Exportar y estadísticas
python main.py export --out urls.csv --has-params --min-priority 30
python main.py stats
```

### Reanudación tras interrupciones
Cada dork guarda un **checkpoint** (`dork_tasks.next_start`) en SQLite. Si el
programa se interrumpe, al relanzar el mismo comando **continúa donde lo dejó**
(sin duplicar resultados gracias al índice UNIQUE).

---

## 6. Auditoría SQLi — cómo funciona

1. **Alcance**: `ScopeGuard` verifica la lista blanca ANTES de cada petición; si el objetivo no está autorizado, lanza `ScopeViolation` y NO se envía nada.
2. **Técnica de errores**: sondas no destructivas (`'`, `"`, `')`, `` ` ``) buscan firmas de error de MySQL, PostgreSQL, MSSQL, Oracle, SQLite o JDBC/ODBC.
3. **Técnica booleana**: compara la respuesta con condición verdadera (`AND 1=1`) y falsa (`AND 1=2`).
4. **Anti-falsos positivos**: payload de control aleatorio + repetición de sondas (reproducibilidad) + comparación de similitud de respuestas.
5. **Evidencia**: `CONFIRMED` → `LIKELY` → `POSSIBLE` → `INFO`.
6. **Remediación**: cada hallazgo incluye recomendaciones y ejemplos de **consultas parametrizadas** en Python, PHP, Java, C# y Node.js.
7. **Registro**: cada petición queda en `audit_log` (URL, estado, latencia, nota) para reproducir el resultado.

### Laboratorio local
```bash
python main.py lab --port 8000
# VULNERABLES: /vulnerable/product?id=1   /vulnerable/search?q=teclado
# CORREGIDOS : /fixed/product?id=1        /fixed/search?q=teclado
```
La demo `lab-demo` audita los 4 endpoints: detecta los vulnerables
(`CONFIRMED·SQLite`) y confirma que los corregidos (parametrizados) no dan
hallazgos. Informe de ejemplo: `reports/audit_report_example.md`.

---

## 7. Pruebas automatizadas

```bash
pytest -q          # 70 tests: dorks, filtros, proxies, analizador,
                   # storage, exportadores, detector SQLi (contra el
                   # laboratorio real) e integración end-to-end
```

---

## 8. Estructura del proyecto

```
urls-dorks-searcher/
├── main.py                     # CLI (gui, search, analyze, audit, lab, lab-demo, export, stats)
├── config.example.json         # configuración de ejemplo
├── proxies.txt                 # plantilla IP:PORT:USER:PASSWORD
├── .env.example                # plantilla de credenciales
├── requirements.txt / pyproject.toml
├── app/
│   ├── config.py  models.py  logging_setup.py
│   ├── search/    dork_builder.py · api_client.py · engine.py · url_filter.py
│   ├── proxies/   manager.py
│   ├── analyzer/  param_analyzer.py
│   ├── sqli/      scope.py · detector.py · runner.py · findings.py
│   │   └── lab/   lab_server.py · lab_data.py
│   ├── storage/   database.py · exporters.py
│   ├── gui/       main_window.py · workers.py
│   └── reporting/ report.py
├── reports/audit_report_example.*   # informe de auditoría de ejemplo
├── docs/dorks_ejemplo.txt
└── tests/                      # suite pytest completa
```

## 9. Solución de problemas

| Problema | Solución |
|---|---|
| `Faltan GOOGLE_API_KEY / GOOGLE_CSE_ID` | Copia `.env.example` a `.env` y rellena las credenciales. |
| `HTTP 429` en los logs | Es el límite de la API: el motor aplica backoff y respeta tu cuota diaria; baja `rate_limit_rps`. |
| `Objetivo FUERA de la lista blanca autorizada` | Añade el dominio a la lista blanca SOLO si tienes autorización. |
| La GUI no arranca en Linux | `sudo apt install libegl1 libgl1 libxkbcommon0` |
| Un proxy se expulsa | Normal tras N fallos: queda de baja temporal `ban_ttl_seconds` y se reintegra solo. |
| Millones de URLs | Todo es streaming (lotes + keyset); no subas `batch_size` por encima de ~2000. |
