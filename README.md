# 😎 URLS GOOGLE DORKS SEARCHER 🌟 — Advanced URL Discovery & SQLi Security Auditor

Programa profesional de OSINT y auditoría de seguridad en Python. Con **Google Dorks
personalizados** descubre **miles de URLs** de los dominios que tú autorices, analiza
cuáles presentan **parámetros GET con superficie a base de datos** (`id`, `product`,
`category`…), y las **audita buscando inyección SQL de forma 100% NO destructiva**.
Todo con **proxies residenciales rotativos** (`IP:PORT:USER:PASSWORD`), almacenamiento
SQLite, exportación TXT/CSV/JSON e **interfaz 100% de consola compatible con Termux
(Android)** — la GUI de escritorio es opcional.

> ## ⚠️ USO RESPONSABLE (léelo antes de nada)
> - **SOLO** para auditorías de seguridad con **autorización expresa** del propietario
>   del sistema: pentesting contractual, tu propia infraestructura o laboratorios
>   locales. Auditar sitios de terceros sin permiso es **delito** en la práctica
>   totalidad de los países.
> - El motor de búsqueda exige una **lista blanca de dominios autorizados**: si el
>   dominio no está en ella, la petición no se ejecuta.
> - El módulo SQLi es **no destructivo**: solo sondas de error y comparación booleana
>   (`AND 1=1` vs `AND 1=2`). **NO** extrae datos, **NO** enumera credenciales,
>   **NO** evade WAFs, **NO** ejecuta consultas apiladas.
> - Los proxies existen **únicamente para respetar los límites de tasa** del servicio
>   de búsqueda autorizado. Usarlos para evadir CAPTCHAs o bloqueos está prohibido.
> - Que una URL tenga parámetros **NO** significa que sea vulnerable: los hallazgos
>   solo provienen del módulo de auditoría.

---

## 1. Características

| Módulo | Qué hace |
|---|---|
| 🔍 **Motor de dorks** | Operadores `site:`, `inurl:`, `intitle:`, `filetype:`, `intext:`, exclusiones, 11 presets y combinaciones. APIs autorizadas (Google CSE / SerpAPI) o proveedor offline para practicar. Cola asyncio con paginación, deduplicación, filtros, cuota diaria, rate limit y backoff exponencial. **Reanudable** por checkpoints. |
| 🌐 **Proxies residenciales rotativos** | Formato `IP:PORT:USER:PASSWORD` en `proxies.txt`, rotación round-robin/random/least-used, verificación asíncrona, estadísticas por proxy y expulsión temporal de los que fallan. Las contraseñas **nunca** aparecen en logs. |
| 🧭 **Analizador de parámetros** | Detecta parámetros GET relacionados con BD (`id`, `item`, `product`, `category`, `search`…), rutas dinámicas y prioriza la revisión con una puntuación 0–100. |
| 🛡️ **Auditoría SQLi** | Lista blanca verificada **antes de cada petición**, detección por errores y booleana, control anti-falsos-positivos, niveles de evidencia (CONFIRMED / LIKELY / POSSIBLE / INFO), remediación con consultas parametrizadas e informe JSON + Markdown. |
| 🧪 **Laboratorio SQLi local** | Servidor HTTP en `127.0.0.1` con datos ficticios: endpoints vulnerables (concatenación) y corregidos (parametrizados) para practicar y validar reparaciones de forma legal. |
| 🖥️ **Menú de consola** | Interfaz interactiva con **todas** las funciones del programa, sin dependencias gráficas. Funciona en **Linux, Windows, macOS y Termux (Android)**. |
| 🪟 **GUI PySide6 (opcional)** | Paneles de estadísticas, dorks, proxies, URLs, auditoría y botones Iniciar/Pausar/Reanudar/Detener. Solo escritorio: `pip install -r requirements-gui.txt`. |
| 💾 **Almacenamiento y export** | SQLite con índice de deduplicación, checkpoints por dork, cuota por fecha y audit log. Exporta TXT/CSV/JSON **en streaming** (compatible con millones de filas sin cargar memoria). |
| ✅ **Calidad** | Python 3.10+, httpx asíncrono, **82 tests pytest** en verde, credenciales solo por variables de entorno. |

---

## 2. Instalación

### 2.1 Windows

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python main.py menu
```

GUI opcional: `pip install -r requirements-gui.txt` y luego `python main.py gui`.

### 2.2 Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py menu
```

> Si la GUI (opcional) se queja de librerías Qt en Linux:
> `sudo apt install libegl1 libgl1 libxkbcommon0 libdbus-1-3 libfontconfig1`

### 2.3 📱 Termux (Android) — paso a paso

> **Importante:** instala Termux desde **F-Droid** (<https://f-droid.org/packages/com.termux/>),
> no desde Play Store (la versión de Play está obsoleta y da errores).
>
> En Termux **no existe la GUI PySide6** (Android no la soporta), pero **no la
> necesitas**: el menú de consola tiene todas las funciones.

**Paso 1 — Prepara Termux** (solo la primera vez):

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git nano
```

**Paso 2 — Descarga el proyecto:**

```bash
git clone https://github.com/HacheJotaDev/DorkSearch-.git
cd DorkSearch-
```

**Paso 3 — Instala las dependencias** (ligeras: httpx + dotenv; sin GUI):

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Paso 4 — Ejecuta:**

```bash
python main.py menu
```

Verás el banner y el menú principal (sección 4). Para la primera prueba **no
necesitas credenciales ni proxies**: elige la opción **7 (Demo completa)** y verás
el laboratorio local en acción.

**Atajos y utilidades en Termux:**

| Acción | Cómo |
|---|---|
| Ctrl+C (interrumpir) | **Volume Down + C** |
| Evitar que Android mate el proceso | `termux-wake-lock` (instala antes: `pkg install termux-api`) |
| Acceder a la memoria compartida | `termux-setup-storage` (una sola vez) |
| Editar `.env` / `proxies.txt` | `nano .env` · `nano proxies.txt` |
| Instalación en un solo paso | `bash scripts/install_termux.sh` |

Guía ampliada de Termux: [`docs/TERMUX.md`](docs/TERMUX.md).

---

## 3. Credenciales y configuración

### 3.1 Credenciales de la API de búsqueda (solo si usarás Google/SerpAPI)

Sin credenciales puedes hacer **TODO** en modo local/offline (demo, laboratorio,
fixtures). Para buscar en Google de verdad:

1. Entra en <https://console.cloud.google.com> → crea un proyecto → habilita
   **Custom Search API** → crea una **API Key**.
2. En <https://programmablesearchengine.google.com> crea un motor de búsqueda y
   copia el **Search engine ID (cx)**.
3. Edita `.env` (cópialo antes de `.env.example`):

   ```
   GOOGLE_API_KEY=tu_clave
   GOOGLE_CSE_ID=tu_cx
   ```

   (Alternativa: define `SERPAPI_KEY` y usa el proveedor `serpapi`.)

Las credenciales **nunca** van en el código ni en el repo: solo en `.env`, que el
`.gitignore` excluye automáticamente.

### 3.2 `config.json` (opcional)

Copia `config.example.json` a `config.json` y ajusta. Secciones principales:

| Sección | Claves útiles |
|---|---|
| `search` | `provider` (`google_cse`/`serpapi`/`offline`), `max_results_per_dork`, `max_total_results`, `max_api_requests_per_day` (cuota), `concurrency`, `rate_limit_rps`, `authorized_domains` (lista blanca) |
| `proxies` | `file`, `strategy` (`round_robin`/`random`/`least_used`), `max_consecutive_failures`, `ban_ttl_seconds` |
| `sqli` | `allowed_domains`, `techniques` (`error`, `boolean`), `max_payloads_per_param`, `max_requests_per_audit` |
| `storage` / `export` | `database`, `batch_size`, `dir` |

### 3.3 `proxies.txt`

Un proxy por línea con el formato de tu proveedor residencial autorizado:

```
IP:PORT:USER:PASSWORD
```

Ejemplo: `192.0.2.10:3128:usuario1:clave1` (la contraseña puede contener `:`;
las líneas que empiezan por `#` son comentarios). Valida con:

```bash
python main.py proxies                  # valida formato, sin red
python main.py proxies --check-network  # prueba conectividad real de cada proxy
```

---

## 4. Cómo ejecutarlo: el menú de consola

```bash
python main.py menu
```

Es el modo recomendado en **Termux, SSH y servidores**. Al arrancar verás:

```
==============================================================
  URLS GOOGLE DORKS SEARCHER - MODO CONSOLA  v1.1.0
  Advanced URL Discovery & SQLi Security Auditor
==============================================================
  Uso responsable: SOLO objetivos con AUTORIZACION expresa.

  1) Busqueda masiva de URLs con dorks
  2) Analizar / priorizar URLs almacenadas
  3) Exportar URLs (TXT / CSV / JSON)
  4) Estadisticas de la base de datos
  5) Auditoria SQLi de una URL (no destructiva)
  6) Iniciar laboratorio SQLi local
  7) Demo completa (laboratorio + auditoria + informe)
  8) Comprobar proxies residenciales (proxies.txt)
  9) Ver configuracion activa
  0) Salir
```

Escribe el número y pulsa Enter. Con **Ctrl+C** vuelves al menú (o sales si estás
en el menú principal). Cada opción te pregunta lo que necesita y muestra los
valores por defecto entre corchetes `[así]`: pulsa Enter para aceptarlos.

### Qué pregunta cada opción

**Opción 1 — Búsqueda con dorks** (el corazón del programa):

| Pregunta | Qué poner |
|---|---|
| `Proveedor` | `google_cse` (con credenciales), `serpapi` o `offline` (práctica sin red) |
| `Presets separados por coma` | Nombres de la tabla 5.1 (p. ej. `php_id,param_id_generico`) o vacío |
| `Dorks literales` | Tus dorks con comillas, p. ej. `site:miweb.com inurl:producto.php?id=` (varios separados por coma) |
| `Fichero de dorks` | Ruta a un fichero con un dork por línea (`docs/dorks_ejemplo.txt` es un ejemplo) |
| `Dominios AUTORIZADOS` | La lista blanca, p. ej. `miweb.com` (Enter sin escribir usa la del config) |
| `Activar rotacion de proxies (s/n)` | `s` solo si cargaste `proxies.txt` |
| `Exportar al terminar` | Ruta tipo `exports/urls.csv` o vacío |
| `Fixture JSON` (solo offline) | Ruta a un JSON `{"*": ["https://dom.com/p.php?id=1", ...]}` |

Antes de lanzar la búsqueda, el menú te recuerda que los dominios deben estar
**autorizados por su propietario**. Necesita al menos un dork y al menos un dominio.

**Opción 5 — Auditoría SQLi:** pide la URL objetivo, los dominios autorizados y te
obliga a escribir **`SI`** para confirmar que tienes autorización expresa. Sin
esa confirmación no se envía ninguna petición.

**Opción 3 — Exportar:** pide fichero de salida (`exports/urls.txt`),
filtros opcionales (dominio, extensión como `php`, solo URLs con parámetros,
prioridad mínima 0–100 calculada por el analizador).

**Opción 8 — Proxies:** pide si quieres probar conectividad real (`s/n`). Muestra
cada proxy con credenciales enmascaradas (`user:***@host:port`) y un resumen.

**Opciones 2, 4, 6, 7, 9** se ejecutan directo (análisis, estadísticas,
laboratorio en el puerto que indiques, demo completa y vista de configuración).

### Ejemplo de sesión completa en Termux (offline, sin credenciales)

```
$ python main.py menu
Selecciona una opcion [0-9]: 1
  Proveedor (google_cse / serpapi / offline) [google_cse]: offline
  Presets separados por coma [...] : php_id
  Dorks literales separados por coma [...] : (Enter)
  Fichero de dorks (uno por linea, opcional) []: (Enter)
  Dominios AUTORIZADOS separados por coma []: mipractica.local
  Activar rotacion de proxies (solo rate limits) (s/n) [n]: (Enter)
  Exportar al terminar (.txt/.csv/.json, vacio = no) []: exports/urls.txt
  Fixture JSON para el proveedor offline (opcional) []: fixture.json
  >> Confirma que TODOS los dominios estan autorizados...
[el motor corre: páginas, deduplicación, checkpoints...]
== RESULTADO ==  { "urls_found": ..., "dorks_completed": 1, ... }
Exportadas N URLs a exports/urls.txt
```

Y la primera vez prueba la **opción 7 (demo completa)**: arranca el laboratorio,
audita sus 4 endpoints y genera `reports/audit_report_example.md`:

```
== DEMO: laboratorio SQLi local con datos ficticios ==
  http://127.0.0.1:39059/vulnerable/product?id=1    -> [CONFIRMED·SQLite]
  http://127.0.0.1:39059/vulnerable/search?q=teclado -> [CONFIRMED·SQLite]
  http://127.0.0.1:39059/fixed/product?id=1          -> [sin hallazgos]
  http://127.0.0.1:39059/fixed/search?q=teclado      -> [sin hallazgos]
Resumen: {'targets_audited': 4, 'findings': 2, 'confirmed': 2, ...}
```

---

## 5. Cómo usarlo por CLI (subcomandos)

Todo lo del menú también se puede lanzar directo, ideal para scripts:

```bash
python main.py --version                       # versión
python main.py menu                            # menú interactivo

# ---- Búsqueda ----
python main.py search --list-presets           # ver los 11 presets
python main.py search --domain ejemplo.com \
    --preset php_id --preset param_id_generico \
    --out exports/urls.json                    # buscar y exportar
python main.py search --domain ejemplo.com \
    --dork 'site:ejemplo.com inurl:producto.php?id='
python main.py search --domain ejemplo.com --dorks-file docs/dorks_ejemplo.txt
python main.py search --domain ejemplo.com --preset php_id --use-proxies
python main.py search --provider offline --domain demo.local \
    --offline-fixture fixture.json --dork 'site:demo.local inurl:id='

# ---- Análisis, exportación y estadísticas ----
python main.py analyze                         # prioriza parámetros (0-100)
python main.py stats                           # resumen de la BD
python main.py export --out urls.csv --has-params --min-priority 30
python main.py export --out urls.txt --domain-filter ejemplo.com --ext php

# ---- Auditoría SQLi (no destructiva) ----
python main.py audit --url "http://127.0.0.1:8000/vulnerable/product?id=1" \
    --domain 127.0.0.1

# ---- Laboratorio y proxies ----
python main.py lab --port 8000                 # laboratorio local interactivo
python main.py lab-demo                        # demo completa + informe ejemplo
python main.py proxies                         # validar proxies.txt (sin red)
python main.py proxies --check-network         # probar conectividad real
```

### 5.1 Presets de dorks incluidos

| Preset | Consulta generada |
|---|---|
| `php_id` | `inurl:.php?id=` |
| `asp_id` | `inurl:.asp?id=` |
| `jsp_id` | `inurl:.jsp?id=` |
| `param_id_generico` | `(inurl:id= OR inurl:item= OR inurl:product= OR inurl:category=)` |
| `paginas_login` | `(inurl:login OR inurl:signin) (intitle:login OR intitle:signin)` |
| `paneles_admin` | `(inurl:admin OR inurl:panel) (intitle:admin OR intitle:panel)` |
| `listado_directorios` | `intitle:index of` |
| `backups_sql` | `(inurl:backup OR inurl:dump OR inurl:db) (filetype:sql OR filetype:bak)` |
| `config_env` | `inurl:config (filetype:env OR filetype:conf OR filetype:cfg)` |
| `endpoints_api` | `(inurl:api/v1 OR inurl:api/v2) filetype:json` |
| `formularios_upload` | `inurl:upload (filetype:php OR filetype:asp OR filetype:aspx OR filetype:jsp)` |

> Recuerda: en `search` el argumento `--domain` es la **lista blanca** — las URLs
> de otros dominios se descartan automáticamente aunque las devuelva la API.

### 5.2 Reanudación tras interrupciones

Cada dork guarda un **checkpoint** (`dork_tasks.next_start`) en SQLite. Si el
programa se corta (o cierras Termux), al relanzar **el mismo comando continúa
donde lo dejó** y no duplica resultados (índice UNIQUE).

---

## 6. Flujo de trabajo recomendado (de cero a informe)

1. **Prueba el entorno**: `python main.py menu` → opción **7** (demo completa).
2. **Busca URLs** (opción 1) sobre tus dominios autorizados, con el preset que
   toque y `--out`/export al terminar.
3. **Analiza** (opción 2): puntúa cada URL 0–100 según lo "interesante" de sus
   parámetros para una revisión SQLi.
4. **Exporta** (opción 3) filtrando, p. ej., `--min-priority 30 --has-params`.
5. **Audita** (opción 5) las URLs de mayor prioridad — recuerda escribir `SI` —
   o con `python main.py audit --url ... --domain ...`.
6. **Lee el informe** en `reports/audit_report.md` (+ JSON): evidencia, técnica,
   motor detectado, reproducibilidad y remediación con **consultas parametrizadas**
   en Python, PHP, Java, C# y Node.js.
7. **Verifica la reparación**: vuelve a auditar tras parametrizar; el laboratorio
   (`/fixed/...`) demuestra que los endpoints corregidos no dan hallazgos.

---

## 7. Auditoría SQLi — cómo funciona (y qué NO hace)

1. **Alcance**: `ScopeGuard` verifica la lista blanca **antes** de cada petición;
   si el objetivo no está autorizado lanza `ScopeViolation` y no se envía nada.
2. **Técnica de errores**: sondas no destructivas (`'`, `"`, `')`, `` ` ``) buscan
   firmas de error de MySQL, PostgreSQL, MSSQL, Oracle, SQLite o JDBC/ODBC.
3. **Técnica booleana**: compara la respuesta con condición verdadera (`AND 1=1`)
   y falsa (`AND 1=2`).
4. **Anti-falsos positivos**: payload de control aleatorio + repetición de sondas
   (reproducibilidad) + comparación de similitud de respuestas.
5. **Evidencia**: `CONFIRMED` → `LIKELY` → `POSSIBLE` → `INFO`.
6. **Remediación**: cada hallazgo incluye recomendaciones y ejemplos de
   **consultas parametrizadas** en Python, PHP, Java, C# y Node.js.
7. **Registro**: cada petición queda en la tabla `audit_log` (URL, estado,
   latencia, nota) para reproducir el resultado.

**NO hace**: extraer datos de bases de datos, enumerar credenciales, evadir WAFs,
consultas apiladas ni ataques automatizados a sitios públicos sin autorización.

### Laboratorio local (para practicar legalmente)

```bash
python main.py lab --port 8000
# Endpoints VULNERABLES: /vulnerable/product?id=1   /vulnerable/search?q=teclado
# Endpoints CORREGIDOS : /fixed/product?id=1        /fixed/search?q=teclado
# Utilidad             : /lab/reset
```

Los vulnerables concatenan SQL (para que veas la detección en vivo); los
corregidos usan **consultas parametrizadas** (para validar la reparación).

---

## 8. Pruebas automatizadas

```bash
pytest -q          # 82 tests: dorks, filtros, proxies, analizador,
                   # storage, exportadores, detector SQLi (contra el
                   # laboratorio real), integración end-to-end, menú de
                   # consola y subcomando proxies
```

---

## 9. Estructura del proyecto

```
urls-dorks-searcher/
├── main.py                     # CLI + menú (menu, proxies, search, analyze, audit, lab, lab-demo, export, stats, gui)
├── config.example.json         # configuración de ejemplo
├── proxies.txt                 # plantilla IP:PORT:USER:PASSWORD
├── .env.example                # plantilla de credenciales
├── requirements.txt            # núcleo (Termux-compatible)
├── requirements-gui.txt        # GUI opcional (escritorio)
├── pyproject.toml
├── app/
│   ├── console_menu.py         # menú interactivo de consola (Termux OK)
│   ├── config.py  models.py  logging_setup.py
│   ├── search/    dork_builder.py · api_client.py · engine.py · url_filter.py
│   ├── proxies/   manager.py
│   ├── analyzer/  param_analyzer.py
│   ├── sqli/      scope.py · detector.py · runner.py · findings.py
│   │   └── lab/   lab_server.py · lab_data.py
│   ├── storage/   database.py · exporters.py
│   ├── gui/       main_window.py · workers.py          (opcional)
│   └── reporting/ report.py
├── scripts/install_termux.sh   # instalador automático para Termux
├── reports/audit_report_example.*   # informe de auditoría de ejemplo
├── docs/TERMUX.md · docs/dorks_ejemplo.txt
└── tests/                      # suite pytest completa (82 tests)
```

## 10. Solución de problemas

| Problema | Solución |
|---|---|
| `Faltan GOOGLE_API_KEY / GOOGLE_CSE_ID` | Copia `.env.example` a `.env` y rellena las credenciales — o usa el proveedor `offline` / la demo (opción 7), que no necesitan red. |
| `HTTP 429` en los logs | Límite de la API: el motor aplica backoff y respeta tu cuota diaria; baja `rate_limit_rps`. |
| `Objetivo FUERA de la lista blanca autorizada` | Añade el dominio SOLO si tienes autorización expresa. |
| `PySide6` no está instalado (GUI) | Es opcional: `pip install -r requirements-gui.txt`, o usa `python main.py menu`. En Termux la GUI no está soportada. |
| Un proxy se expulsa | Normal tras N fallos: queda de baja temporal `ban_ttl_seconds` y se reintegra solo. |
| Millones de URLs | Todo es streaming (lotes + keyset); no subas `batch_size` por encima de ~2000. |
| **Termux:** `pip` falla compilando | `pkg install -y build-essential libffi openssl rust binutils` y reintenta. |
| **Termux:** no hay red desde Python | Prueba con Wi-Fi; algunas redes móviles bloquean ciertos hosts. |
| **Termux:** se cierra con la pantalla apagada | `termux-wake-lock` antes de búsquedas largas. |
| **Termux:** Ctrl+C | Volume Down + C. |
