"""Smoke test de la GUI: la ventana se instancia y se destruye sin errores
(en modo offscreen, sin necesidad de pantalla)."""
import os


def test_gui_instantia_offscreen(tmp_path):
    try:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        from app.config import AppConfig
        from app.gui.main_window import MainWindow
    except ImportError as e:
        import pytest
        pytest.skip(f"PySide6/Qt no disponible en este entorno ({e}); "
                    "la GUI se verifica en el equipo del usuario")

    cfg = AppConfig()
    cfg.storage.database = str(tmp_path / "gui.db")
    qt_app = QApplication.instance() or QApplication([])
    win = MainWindow(cfg)
    assert win.windowTitle().startswith("URLS Google Dorks Searcher")
    assert win.tabs.count() == 5
    win.close()
