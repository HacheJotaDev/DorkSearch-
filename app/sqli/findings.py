"""Niveles de evidencia y recomendaciones de remediación (consultas
parametrizadas por lenguaje)."""
from __future__ import annotations

EVIDENCE_LEVELS: dict[str, int] = {
    "INFO": 10,
    "POSSIBLE": 20,
    "LIKELY": 30,
    "CONFIRMED": 40,
}
EVIDENCE_NAMES: dict[int, str] = {v: k for k, v in EVIDENCE_LEVELS.items()}

REMEDIATION_BASE: list[str] = [
    "Corrige usando consultas parametrizadas / prepared statements: NUNCA concatenes "
    "entrada del usuario en el SQL (véase el parámetro 'id' inyectado en el hallazgo).",
    "Valida y normaliza la entrada según el tipo esperado (enteros con cast, "
    "enumeraciones con listas blancas, longitudes máximas).",
    "Aplica el principio de mínimo privilegio al usuario de BD de la aplicación "
    "(solo SELECT/INSERT/UPDATE necesarios, sin DDL ni superusuario).",
    "Desactiva los mensajes de error detallados de la base de datos en producción; "
    "registra los errores en un log seguro y devuelve páginas genéricas.",
    "Considera un ORM o una capa de acceso a datos que use sentencias preparadas por defecto.",
]

REMEDIATION_SNIPPETS: dict[str, str] = {
    "Python (sqlite3/DB-API)": 'cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))',
    "Python (SQLAlchemy)": 'session.query(Product).filter(Product.id == product_id).first()',
    "PHP (PDO)": '$stmt = $pdo->prepare("SELECT * FROM products WHERE id = :id"); $stmt->execute(["id" => $product_id]);',
    "Java (JDBC)": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM products WHERE id = ?"); ps.setInt(1, productId);',
    "C# (ADO.NET)": 'using var cmd = new SqlCommand("SELECT * FROM products WHERE id = @id", conn); cmd.Parameters.Add("@id", SqlDbType.Int).Value = productId;',
    "Node.js (pg/mysql2)": 'await pool.query("SELECT * FROM products WHERE id = $1", [productId]);',
}
