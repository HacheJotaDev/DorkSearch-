# 📱 Guía de instalación y uso en Termux (Android)

El programa funciona **100% por consola**: todas las funciones (búsqueda con
dorks, análisis, exportación, auditoría SQLi no destructiva, laboratorio y
proxies) están disponibles en el **menú interactivo**, sin necesidad de la GUI.

> PySide6 (la ventana gráfica) **no está soportada en Android**. En Termux no
> la instales: el modo consola `python main.py menu` tiene todo lo demás.

---

## 1. Instalación paso a paso

1. Instala **Termux desde F-Droid** (<https://f-droid.org/packages/com.termux/>).
   La versión de Play Store está obsoleta y da errores de paquetes.

2. Abre Termux y actualiza paquetes:

   ```bash
   pkg update -y && pkg upgrade -y
   pkg install -y python git nano
   ```

3. Copia el proyecto a Termux (elige una opción):

   ```bash
   # Opción A: clonar desde GitHub
   git clone https://github.com/HacheJotaDev/DorkSearch-.git
   cd DorkSearch-

   # Opción B: descargar el ZIP y descomprimirlo
   pkg install -y wget unzip
   wget https://tmpfiles.org/dl/w1ATJLNRv2zy/urls-dorks-searcher.zip   # enlace temporal
   unzip urls-dorks-searcher.zip && cd urls-dorks-searcher
   ```

4. Instala las dependencias del núcleo (ligeras, sin GUI):

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   O directamente con el instalador automático:

   ```bash
   bash scripts/install_termux.sh
   ```

## 2. Arranque

```bash
python main.py menu          # menú interactivo completo (recomendado)
```

Subcomandos directos equivalentes:

```bash
python main.py search --domain tudominio.com --preset php_id --provider offline
python main.py analyze
python main.py stats
python main.py export --out exports/urls.csv --has-params
python main.py proxies                        # valida proxies.txt (sin red)
python main.py proxies --check-network        # prueba conectividad real
python main.py lab-demo                       # demo local con datos ficticios
python main.py audit --url "http://127.0.0.1:8000/vulnerable/product?id=1" \
                     --domain 127.0.0.1
```

## 3. Configuración en Termux

```bash
cp .env.example .env
nano .env            # GOOGLE_API_KEY / GOOGLE_CSE_ID (o SERPAPI_KEY)
nano proxies.txt     # tus proxies residenciales: IP:PORT:USER:PASSWORD
```

Las credenciales viven **solo** en `.env`; nunca en el código ni en el chat.

- Sin credenciales de API puedes usar el proveedor `offline` (fixture JSON)
  para probar todo el motor sin gastar cuota.
- El laboratorio (`python main.py lab`) corre en `127.0.0.1` dentro del propio
  Android: perfecto para practicar SQLi de forma legal y sin datos reales.

## 4. Almacenamiento

SQLite y exportaciones se crean en las carpetas del proyecto
(`data/urls.db`, `exports/`, `reports/`). Si quieres que apunten a la
memoria compartida de Android:

```bash
termux-setup-storage          # concede acceso a /storage (una sola vez)
```

y ajusta `storage.database` en tu `config.json`.

## 5. Buenas prácticas en móvil

- Usa **concuencia baja** (`search.concurrency = 1` o `2`) y `rate_limit_rps`
  moderado: las APIs de búsqueda tienen cuota diaria y el móvil puede
  suspender procesos en segundo plano.
- Mantén la pantalla activa durante búsquedas largas (o usa `termux-wake-lock`,
  disponible con `pkg install termux-api`).
- Ejecuta auditorías solo contra dominios **autorizados por escrito**.

## 6. Problemas frecuentes

| Síntoma | Solución |
|---|---|
| `pip` falla compilando algo | `pkg install -y build-essential libffi openssl rust binutils` y reintenta |
| No hay red desde Python | Algunas redes móviles bloquean peticiones; prueba Wi-Fi o revisa APN |
| `matplotlib`/`PySide6` errors | No corresponden: este proyecto no los usa en modo consola |
| Tecla Ctrl+C | En Termux: botón **volume-down + C** |
| Quiero la GUI | Solo en PC: `pip install -r requirements-gui.txt` |
