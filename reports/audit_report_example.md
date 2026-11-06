# Informe de auditoría SQLi (no destructiva)

- **Generado:** 2026-11-06T17:19:30+00:00
- **Herramienta:** Advanced URL Discovery & SQLi Security Auditor
- **Contexto:** {"targets": 4, "origen": "lab-demo", "entorno": "laboratorio LOCAL con datos ficticios (127.0.0.1)"}

## Alcance autorizado

- `127.0.0.1`
> Auditoría limitada EXCLUSIVAMENTE a los dominios autorizados por el propietario del sistema. Verificación de alcance antes de cada petición.

## Resumen

- Objetivos auditados: **4**
- Hallazgos: **2** (Confirmados: 2 · Probables: 0 · Posibles: 0 · Informativos: 0)

## Hallazgos

### 1. [CONFIRMED] http://127.0.0.1:34675/vulnerable/product?id=1 — parámetro `id`

- **Técnica:** error · **Motor:** SQLite
- **Detalle:** El parámetro 'id' provoca un error visible de SQLite al alterar su valor (sonda no destructiva '''). Reproducible: sí.
- **Evidencia:** `{"error": "unrecognized token: \"'1''\"", "sql": "SELECT id, name, price, stock FROM prod`
- **Snapshot de la petición (reproducibilidad):** `{"url": "http://127.0.0.1:34675/vulnerable/product?id=1%27", "method": "GET", "status": 500, "length": 111, "elapsed_ms": 3.5, "probe": "'", "repeat_status": 500}`
- **Recomendaciones:**
    - Corrige usando consultas parametrizadas / prepared statements: NUNCA concatenes entrada del usuario en el SQL (véase el parámetro 'id' inyectado en el hallazgo).
    - Motor de base de datos detectado: SQLite.
    - Valida y normaliza la entrada según el tipo esperado (enteros con cast, enumeraciones con listas blancas, longitudes máximas).
    - Aplica el principio de mínimo privilegio al usuario de BD de la aplicación (solo SELECT/INSERT/UPDATE necesarios, sin DDL ni superusuario).
    - Desactiva los mensajes de error detallados de la base de datos en producción; registra los errores en un log seguro y devuelve páginas genéricas.
    - Considera un ORM o una capa de acceso a datos que use sentencias preparadas por defecto.
    - Ejemplos de consultas parametrizadas:
    -   Python (sqlite3/DB-API): cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    -   Python (SQLAlchemy): session.query(Product).filter(Product.id == product_id).first()
    -   PHP (PDO): $stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id"); $stmt->execute(["id" => $product_id]);
    -   Java (JDBC): PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id = ?"); ps.setInt(1, productId);
    -   C# (ADO.NET): using var cmd = new SqlCommand("SELECT * FROM products WHERE id = @id", conn); cmd.Parameters.Add("@id", SqlDbType.Int).Value = productId;
    -   Node.js (pg/mysql2): await pool.query("SELECT * FROM products WHERE id = $1", [productId]);

### 2. [CONFIRMED] http://127.0.0.1:34675/vulnerable/search?q=teclado — parámetro `q`

- **Técnica:** error · **Motor:** SQLite
- **Detalle:** El parámetro 'q' provoca un error visible de SQLite al alterar su valor (sonda no destructiva '''). Reproducible: sí.
- **Evidencia:** `{"error": "unrecognized token: \"'\"", "sql": "SELECT id, name, price FROM products WHERE`
- **Snapshot de la petición (reproducibilidad):** `{"url": "http://127.0.0.1:34675/vulnerable/search?q=teclado%27", "method": "GET", "status": 500, "length": 114, "elapsed_ms": 2.6, "probe": "'", "repeat_status": 500}`
- **Recomendaciones:**
    - Corrige usando consultas parametrizadas / prepared statements: NUNCA concatenes entrada del usuario en el SQL (véase el parámetro 'id' inyectado en el hallazgo).
    - Motor de base de datos detectado: SQLite.
    - Valida y normaliza la entrada según el tipo esperado (enteros con cast, enumeraciones con listas blancas, longitudes máximas).
    - Aplica el principio de mínimo privilegio al usuario de BD de la aplicación (solo SELECT/INSERT/UPDATE necesarios, sin DDL ni superusuario).
    - Desactiva los mensajes de error detallados de la base de datos en producción; registra los errores en un log seguro y devuelve páginas genéricas.
    - Considera un ORM o una capa de acceso a datos que use sentencias preparadas por defecto.
    - Ejemplos de consultas parametrizadas:
    -   Python (sqlite3/DB-API): cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    -   Python (SQLAlchemy): session.query(Product).filter(Product.id == product_id).first()
    -   PHP (PDO): $stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id"); $stmt->execute(["id" => $product_id]);
    -   Java (JDBC): PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id = ?"); ps.setInt(1, productId);
    -   C# (ADO.NET): using var cmd = new SqlCommand("SELECT * FROM products WHERE id = @id", conn); cmd.Parameters.Add("@id", SqlDbType.Int).Value = productId;
    -   Node.js (pg/mysql2): await pool.query("SELECT * FROM products WHERE id = $1", [productId]);

## Metodología

- Detección NO destructiva: firmas de error de BD y comparación booleana (1=1 vs 1=2).
- No se extraen datos, no se enumeran credenciales, no se evaden controles ni WAFs.
- Cada petición se valida contra la lista blanca autorizada antes de ejecutarse.
- Las sondas se repiten para verificar reproducibilidad y se usan payloads de control aleatorios para descartar falsos positivos.
