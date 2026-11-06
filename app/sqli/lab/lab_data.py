"""Datos FICTICIOS del laboratorio SQLi local.

Todas las filas son inventadas (tienda imaginaria) y los correos usan
example.com. Nada de datos reales.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

FICTIONAL_PRODUCTS = [
    (1, "Teclado mecánico X1", 49.99, 120),
    (2, "Ratón óptico Pro", 25.50, 300),
    (3, "Monitor LED 24\"", 129.00, 45),
    (4, "Auriculares BT Sound", 39.90, 210),
    (5, "Webcam HD Stream", 59.00, 80),
    (6, "Silla ergonómica Alpha", 189.99, 15),
    (7, "Escritorio ajustable Delta", 259.00, 8),
    (8, "Base refrigeradora Cool", 22.75, 95),
    (9, "Hub USB 7 puertos", 18.30, 150),
    (10, "SSD externo 1TB", 89.99, 60),
]

FICTIONAL_USERS = [
    (1, "ana.demo", "ana.demo@example.com"),
    (2, "bruno.demo", "bruno.demo@example.com"),
    (3, "carla.demo", "carla.demo@example.com"),
    (4, "diego.demo", "diego.demo@example.com"),
    (5, "elena.demo", "elena.demo@example.com"),
]


def init_lab_db(path: str | Path = "data/lab.db") -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.executescript(
        """
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS users;
        CREATE TABLE products(
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL,
            stock INTEGER
        );
        CREATE TABLE users(
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        );
        """
    )
    conn.executemany("INSERT INTO products VALUES (?,?,?,?)", FICTIONAL_PRODUCTS)
    conn.executemany("INSERT INTO users VALUES (?,?,?)", FICTIONAL_USERS)
    conn.commit()
    return conn
