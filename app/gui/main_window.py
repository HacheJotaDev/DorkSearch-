"""Ventana principal PySide6 del URLS GOOGLE DORKS SEARCHER.

Pestañas: Panel (estadísticas), Búsqueda (dorks), URLs (lista+filtros+export),
Proxies (gestor residencial rotativo) y Auditoría SQLi (no destructiva).
Toda tarea larga se ejecuta en workers (QThread) para NO bloquear la UI.
"""
from __future__ import annotations

import json
import time
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..analyzer.param_analyzer import analyze_database, priority_label
from ..config import AppConfig, load_config
from ..proxies.manager import ProxyManager, ProxyManagerError
from ..reporting.report import generate_report
from ..search.api_client import ProviderError, create_provider
from ..search.dork_builder import PRESET_NAMES, PRESETS, build_query, dorks_from_presets
from ..search.engine import SearchEngine
from ..search.url_filter import UrlFilter, UrlFilterer
from ..storage.database import Database
from ..storage.exporters import export_csv, export_json, export_txt
from .workers import AuditWorker, ProxyCheckWorker, SearchWorker

APP_TITLE = "URLS Google Dorks Searcher — Advanced URL Discovery & SQLi Security Auditor"
MAX_ROWS_IN_TABLE = 5000


def _init_table(t: QTableWidget, headers: list[str]) -> None:
    t.clear()
    t.setColumnCount(len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)


class MainWindow(QMainWindow):
    def __init__(self, config: AppConfig):
        super().__init__()
        self.cfg = config
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 780)
        self.db = Database(self.cfg.storage.database)
        self.engine: SearchEngine | None = None
        self.search_worker: SearchWorker | None = None
        self.proxy_worker: ProxyCheckWorker | None = None
        self.audit_worker: AuditWorker | None = None
        self.proxy_manager: ProxyManager | None = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self._build_dashboard_tab(), "Panel")
        self.tabs.addTab(self._build_search_tab(), "Búsqueda (Dorks)")
        self.tabs.addTab(self._build_urls_tab(), "URLs")
        self.tabs.addTab(self._build_proxies_tab(), "Proxies")
        self.tabs.addTab(self._build_sqli_tab(), "Auditoría SQLi")
        self._build_menu()
        self.statusBar().showMessage(
            "Listo · USA ESTA HERRAMIENTA SOLO EN SISTEMAS AUTORIZADOS")
        self.refresh_dashboard()

    # ================= MENÚ =================
    def _build_menu(self) -> None:
        m_file = self.menuBar().addMenu("&Archivo")
        act_load = QAction("Cargar configuración JSON…", self)
        act_load.triggered.connect(self._load_config_dialog)
        act_save = QAction("Guardar configuración JSON…", self)
        act_save.triggered.connect(self._save_config_dialog)
        act_quit = QAction("Salir", self)
        act_quit.triggered.connect(self.close)
        for a in (act_load, act_save):
            m_file.addAction(a)
        m_file.addSeparator()
        m_file.addAction(act_quit)

        m_help = self.menuBar().addMenu("Ay&uda")
        act_about = QAction("Acerca de / uso responsable", self)
        act_about.triggered.connect(self._about)
        m_help.addAction(act_about)

    def _load_config_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Cargar configuración", "", "JSON (*.json)")
        if not path:
            return
        try:
            self.cfg = load_config(path)
            QMessageBox.information(self, "Configuración", f"Configuración cargada:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo cargar: {e}")

    def _save_config_dialog(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Guardar configuración", "config.json",
                                              "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.cfg.to_dict(), f, indent=2, ensure_ascii=False)
        QMessageBox.information(self, "Configuración", f"Guardada en:\n{path}")

    def _about(self) -> None:
        QMessageBox.about(
            self, "Acerca de",
            "<b>Advanced URL Discovery &amp; SQLi Security Auditor</b><br><br>"
            "Herramienta para auditorías de seguridad AUTORIZADAS:<br>"
            "· Lista blanca de dominios obligatoria.<br>"
            "· Auditoría SQLi 100% no destructiva.<br>"
            "· Prohibido usarla para extraer BDs ajenas, enumerar credenciales, "
            "evadir WAFs o atacar sitios públicos sin permiso.<br><br>"
            "Proxies: únicamente para respetar límites de tasa del servicio autorizado."
        )

    # ================= PANEL =================
    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        box = QGroupBox("Estadísticas de la base de datos")
        form = QFormLayout(box)
        self.lbl_total = QLabel("0")
        self.lbl_domains = QLabel("0")
        self.lbl_params = QLabel("0")
        self.lbl_high = QLabel("0")
        self.lbl_dorks = QLabel("0/0")
        self.lbl_quota = QLabel("0")
        self.lbl_findings = QLabel("0")
        form.addRow("URLs totales (deduplicadas):", self.lbl_total)
        form.addRow("Dominios únicos:", self.lbl_domains)
        form.addRow("URLs con parámetros:", self.lbl_params)
        form.addRow("Prioridad ALTA (posible interés para revisión autorizada):", self.lbl_high)
        form.addRow("Dorks completados:", self.lbl_dorks)
        form.addRow("Cuota API usada hoy:", self.lbl_quota)
        form.addRow("Hallazgos SQLi registrados:", self.lbl_findings)
        v.addWidget(box)

        btns = QHBoxLayout()
        b1 = QPushButton("Analizar parámetros (priorizar)")
        b1.clicked.connect(self._analyze_params)
        b2 = QPushButton("Refrescar")
        b2.clicked.connect(self.refresh_dashboard)
        btns.addWidget(b1)
        btns.addWidget(b2)
        btns.addStretch(1)
        v.addLayout(btns)
        v.addStretch(1)

        warn = QLabel(
            "⚠️ AVISO: herramienta solo para auditorías de seguridad AUTORIZADAS.\n"
            "La presencia de parámetros NO implica inyección SQL: los hallazgos "
            "provienen exclusivamente del módulo de auditoría no destructiva.")
        warn.setStyleSheet("color: #a06000;")
        warn.setWordWrap(True)
        v.addWidget(warn)
        return w

    def refresh_dashboard(self) -> None:
        s = self.db.stats()
        self.lbl_total.setText(str(s["total_urls"]))
        self.lbl_domains.setText(str(s["unique_domains"]))
        self.lbl_params.setText(str(s["with_params"]))
        self.lbl_high.setText(str(s["high_priority"]))
        self.lbl_dorks.setText(f"{s['dorks_done']}/{s['dorks_total']}")
        self.lbl_quota.setText(str(s["quota_used_today"]))
        self.lbl_findings.setText(str(s["findings"]))

    def _analyze_params(self) -> None:
        def progress(n):
            self.statusBar().showMessage(f"Analizadas {n} URLs…")

        result = analyze_database(self.db, progress=progress)
        self.refresh_dashboard()
        self.statusBar().showMessage(f"Análisis completado: {result['analyzed']} URLs procesadas")
        self.log_box.appendPlainText(f"[analizador] {result['analyzed']} URLs priorizadas")

    # ================= BÚSQUEDA =================
    def _build_search_tab(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        left = QVBoxLayout()

        gb_dorks = QGroupBox("Dorks (uno por línea) — SOLO dominios autorizados")
        dv = QVBoxLayout(gb_dorks)
        self.dorks_edit = QPlainTextEdit()
        self.dorks_edit.setPlaceholderText(
            "site:example.com inurl:product.php?id=\n"
            "site:example.com intitle:\"index of\"")
        dv.addWidget(self.dorks_edit)
        prow = QHBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(PRESET_NAMES)
        b_add = QPushButton("Insertar preset")
        b_add.clicked.connect(self._insert_preset)
        prow.addWidget(self.preset_combo, 1)
        prow.addWidget(b_add)
        dv.addLayout(prow)
        left.addWidget(gb_dorks)

        gb_wl = QGroupBox("Lista blanca de dominios autorizados (OBLIGATORIA)")
        wv = QVBoxLayout(gb_wl)
        self.whitelist_edit = QPlainTextEdit()
        self.whitelist_edit.setPlaceholderText("example.com\nsubdominio.example.com")
        self.whitelist_edit.setMaximumHeight(70)
        wv.addWidget(self.whitelist_edit)
        left.addWidget(gb_wl)

        gb_opt = QGroupBox("Opciones del motor")
        form = QFormLayout(gb_opt)
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["google_cse", "serpapi", "offline"])
        form.addRow("Proveedor API:", self.provider_combo)
        self.spin_rpp = QSpinBox(); self.spin_rpp.setRange(1, 100); self.spin_rpp.setValue(10)
        form.addRow("Resultados por página:", self.spin_rpp)
        self.spin_max_dork = QSpinBox(); self.spin_max_dork.setRange(1, 100000)
        self.spin_max_dork.setValue(100)
        form.addRow("Máx. resultados por dork:", self.spin_max_dork)
        self.spin_max_total = QSpinBox(); self.spin_max_total.setRange(1, 10_000_000)
        self.spin_max_total.setValue(100000)
        form.addRow("Máx. resultados totales:", self.spin_max_total)
        self.spin_quota = QSpinBox(); self.spin_quota.setRange(1, 1_000_000)
        self.spin_quota.setValue(5000)
        form.addRow("Cuota API/día (peticiones):", self.spin_quota)
        self.spin_rps = QDoubleSpinBox(); self.spin_rps.setRange(0.1, 100)
        self.spin_rps.setSingleStep(0.5); self.spin_rps.setValue(1.0)
        form.addRow("Peticiones/seg (rate limit):", self.spin_rps)
        self.spin_conc = QSpinBox(); self.spin_conc.setRange(1, 32); self.spin_conc.setValue(3)
        form.addRow("Workers concurrentes:", self.spin_conc)
        self.chk_use_proxies = QCheckBox("Usar proxies cargados (rotación para respetar límites)")
        form.addRow(self.chk_use_proxies)
        left.addWidget(gb_opt)

        btns = QHBoxLayout()
        self.btn_start = QPushButton("▶ Iniciar")
        self.btn_start.clicked.connect(self._search_start)
        self.btn_pause = QPushButton("⏸ Pausar"); self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(lambda: self.search_worker and self.search_worker.pause())
        self.btn_resume = QPushButton("⏵ Reanudar"); self.btn_resume.setEnabled(False)
        self.btn_resume.clicked.connect(lambda: self.search_worker and self.search_worker.resume())
        self.btn_stop = QPushButton("⏹ Detener"); self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(lambda: self.search_worker and self.search_worker.stop())
        for b in (self.btn_start, self.btn_pause, self.btn_resume, self.btn_stop):
            btns.addWidget(b)
        left.addLayout(btns)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1); self.progress.setValue(0)
        left.addWidget(self.progress)

        gb_log = QGroupBox("Registro de la búsqueda")
        lv = QVBoxLayout(gb_log)
        self.log_box = QPlainTextEdit(); self.log_box.setReadOnly(True)
        lv.addWidget(self.log_box)
        left.addWidget(gb_log, 1)

        right = QVBoxLayout()
        gb_urls = QGroupBox("Últimas URLs descubiertas (en vivo)")
        uv = QVBoxLayout(gb_urls)
        self.live_table = QTableWidget()
        _init_table(self.live_table, ["URL", "Dork", "Prioridad"])
        uv.addWidget(self.live_table)
        right.addWidget(gb_urls, 1)

        h.addLayout(left, 3)
        h.addLayout(right, 2)
        return w

    def _insert_preset(self) -> None:
        name = self.preset_combo.currentText()
        self.dorks_edit.appendPlainText(build_query(PRESETS[name]))

    def _apply_search_options(self) -> None:
        s = self.cfg.search
        s.provider = self.provider_combo.currentText()
        s.results_per_page = self.spin_rpp.value()
        s.max_results_per_dork = self.spin_max_dork.value()
        s.max_total_results = self.spin_max_total.value()
        s.max_api_requests_per_day = self.spin_quota.value()
        s.rate_limit_rps = self.spin_rps.value()
        s.concurrency = self.spin_conc.value()

    def _search_start(self) -> None:
        if self.search_worker and self.search_worker.isRunning():
            QMessageBox.warning(self, "En curso", "Ya hay una búsqueda en ejecución.")
            return
        dorks = [l.strip() for l in self.dorks_edit.toPlainText().splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        if not dorks:
            QMessageBox.warning(self, "Sin dorks", "Introduce al menos un dork o inserta un preset.")
            return
        whitelist = [l.strip().lower() for l in self.whitelist_edit.toPlainText().splitlines()
                     if l.strip()]
        if not whitelist:
            QMessageBox.warning(
                self, "Lista blanca obligatoria",
                "Define la lista blanca de dominios autorizados.\n"
                "La búsqueda NO se ejecuta sin autorización explícita.")
            return
        self._apply_search_options()
        self.cfg.search.authorized_domains = whitelist
        try:
            provider = create_provider(self.cfg.search)
        except ProviderError as e:
            QMessageBox.critical(self, "Proveedor de búsqueda", str(e))
            return
        proxies = self.proxy_manager if (self.chk_use_proxies.isChecked()
                                         and self.proxy_manager and len(self.proxy_manager)) else None
        if self.chk_use_proxies.isChecked() and proxies is None:
            self.log_box.appendPlainText(
                "[proxies] No hay proxies cargados/válidos: se continúa sin rotación.")
        filterer = UrlFilterer(UrlFilter(allowed_domains=set(whitelist)))
        self.engine = SearchEngine(self.cfg, provider, self.db, filterer,
                                   proxies=proxies, batch_size=self.cfg.storage.batch_size)
        self.search_worker = SearchWorker(self.engine, dorks)
        sw = self.search_worker.signals
        sw.log.connect(self.log_box.appendPlainText)
        sw.log.connect(lambda m: self.statusBar().showMessage(m[:180]))
        sw.urls.connect(self._on_live_urls)
        sw.done.connect(self._search_done)
        sw.error.connect(lambda e: (self.log_box.appendPlainText(f"[ERROR] {e}"),
                                    self._search_done(None)))
        self.progress.setRange(0, len(dorks)); self.progress.setValue(0)
        self._set_search_buttons(running=True)
        self.search_worker.start()

    def _on_live_urls(self, batch: list) -> None:
        for rec in batch[:50]:
            row = self.live_table.rowCount()
            if row >= MAX_ROWS_IN_TABLE:
                self.live_table.removeRow(0)
                row = self.live_table.rowCount()
            self.live_table.insertRow(row)
            self.live_table.setItem(row, 0, QTableWidgetItem(rec.get("url", "")))
            self.live_table.setItem(row, 1, QTableWidgetItem(rec.get("dork", "")))
            self.live_table.setItem(row, 2, QTableWidgetItem(str(rec.get("priority", 0))))
        self.live_table.scrollToBottom()

    def _search_done(self, _stats) -> None:
        self._set_search_buttons(running=False)
        self.refresh_dashboard()
        self.statusBar().showMessage("Búsqueda finalizada")

    def _set_search_buttons(self, running: bool) -> None:
        self.btn_start.setEnabled(not running)
        self.btn_pause.setEnabled(running)
        self.btn_resume.setEnabled(running)
        self.btn_stop.setEnabled(running)

    # ================= URLs =================
    def _build_urls_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        gb_f = QGroupBox("Filtros")
        fh = QHBoxLayout(gb_f)
        self.f_domain = QLineEdit(); self.f_domain.setPlaceholderText("dominio (exacto)")
        self.f_ext = QLineEdit(); self.f_ext.setPlaceholderText("extensión (p.ej. php)")
        self.f_minprio = QSpinBox(); self.f_minprio.setRange(0, 100)
        self.f_minprio.setPrefix("prioridad ≥ ")
        self.f_params = QCheckBox("solo con parámetros")
        b_refresh = QPushButton("Aplicar filtros")
        b_refresh.clicked.connect(self._urls_refresh)
        for widget in (self.f_domain, self.f_ext, self.f_minprio, self.f_params, b_refresh):
            fh.addWidget(widget)
        v.addWidget(gb_f)

        self.urls_table = QTableWidget()
        _init_table(self.urls_table,
                    ["URL", "Dominio", "Parám.", "Relacionados BD", "Prioridad", "Ext", "Dork"])
        v.addWidget(self.urls_table, 1)

        self.urls_count = QLabel("0 URLs")
        v.addWidget(self.urls_count)

        eh = QHBoxLayout()
        b_txt = QPushButton("Exportar TXT"); b_txt.clicked.connect(lambda: self._urls_export("txt"))
        b_csv = QPushButton("Exportar CSV"); b_csv.clicked.connect(lambda: self._urls_export("csv"))
        b_json = QPushButton("Exportar JSON"); b_json.clicked.connect(lambda: self._urls_export("json"))
        for b in (b_txt, b_csv, b_json):
            eh.addWidget(b)
        eh.addStretch(1)
        v.addLayout(eh)
        return w

    def _current_url_filters(self) -> dict:
        return {
            "domain": self.f_domain.text().strip() or None,
            "ext": self.f_ext.text().strip() or None,
            "min_priority": self.f_minprio.value() or None,
            "has_params": self.f_params.isChecked(),
        }

    def _urls_refresh(self) -> None:
        fl = self._current_url_filters()
        rows = list(self.db.iter_urls(batch=500, **fl))
        shown = rows[:MAX_ROWS_IN_TABLE]
        t = self.urls_table
        t.setRowCount(0)
        for r in shown:
            row = t.rowCount()
            t.insertRow(row)
            vals = [r["url"], r["domain"], str(r["params_count"]),
                    r["db_related"], f"{r['priority']} ({priority_label(r['priority'])})",
                    r["ext"], r["dork"]]
            for col, val in enumerate(vals):
                t.setItem(row, col, QTableWidgetItem(str(val)))
        extra = f" (mostrando {len(shown)} de {len(rows)})" if len(rows) > len(shown) else ""
        self.urls_count.setText(f"{len(rows)} URLs{extra}")

    def _urls_export(self, fmt: str) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar URLs", f"urls.{fmt}", f"{fmt.upper()} (*.{fmt})")
        if not path:
            return
        fl = self._current_url_filters()
        exporter = {"txt": export_txt, "csv": export_csv, "json": export_json}[fmt]
        n = exporter(path, self.db.iter_urls(batch=1000, **fl))
        QMessageBox.information(self, "Exportación", f"{n} URLs exportadas a:\n{path}")

    # ================= PROXIES =================
    def _build_proxies_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        gb1 = QGroupBox("Cargar proxies (formato IP:PORT:USER:PASSWORD, uno por línea)")
        f1 = QFormLayout(gb1)
        self.proxies_file = QLineEdit("proxies.txt")
        b_browse = QPushButton("Examinar…")
        b_browse.clicked.connect(self._proxies_browse)
        row = QHBoxLayout()
        row.addWidget(self.proxies_file, 1)
        row.addWidget(b_browse)
        f1.addRow("Fichero:", row)
        self.strategy_combo = QComboBox()
        self.strategy_combo.addItems(["round_robin", "random", "least_used"])
        f1.addRow("Estrategia de rotación:", self.strategy_combo)
        self.spin_ban_fail = QSpinBox(); self.spin_ban_fail.setRange(1, 50); self.spin_ban_fail.setValue(3)
        f1.addRow("Fallos consecutivos antes de expulsar:", self.spin_ban_fail)
        self.spin_ban_ttl = QDoubleSpinBox(); self.spin_ban_ttl.setRange(5, 3600)
        self.spin_ban_ttl.setValue(300)
        f1.addRow("TTL de expulsión (segundos):", self.spin_ban_ttl)
        b_load = QPushButton("Cargar proxies")
        b_load.clicked.connect(self._proxies_load)
        f1.addRow(b_load)
        v.addWidget(gb1)

        gb2 = QGroupBox("Verificación de conectividad")
        f2 = QFormLayout(gb2)
        self.check_url = QLineEdit("https://httpbin.org/ip")
        f2.addRow("URL de prueba:", self.check_url)
        self.spin_check_to = QDoubleSpinBox(); self.spin_check_to.setRange(1, 60)
        self.spin_check_to.setValue(10)
        f2.addRow("Timeout (s):", self.spin_check_to)
        self.spin_check_conc = QSpinBox(); self.spin_check_conc.setRange(1, 64)
        self.spin_check_conc.setValue(10)
        f2.addRow("Verificaciones concurrentes:", self.spin_check_conc)
        b_check = QPushButton("Verificar todos")
        b_check.clicked.connect(self._proxies_check)
        f2.addRow(b_check)
        v.addWidget(gb2)

        self.proxy_table = QTableWidget()
        _init_table(self.proxy_table,
                    ["Proxy (credenciales ocultas)", "Estado", "Peticiones", "Éxitos",
                     "Fallos", "Latencia media (s)", "Expulsado restante (s)"])
        v.addWidget(self.proxy_table, 1)
        self.proxy_count = QLabel("0 proxies cargados")
        v.addWidget(self.proxy_count)
        return w

    def _proxies_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Fichero de proxies", "", "TXT (*.txt)")
        if path:
            self.proxies_file.setText(path)

    def _proxies_load(self) -> None:
        try:
            self.proxy_manager = ProxyManager(
                strategy=self.strategy_combo.currentText(),
                max_consecutive_failures=self.spin_ban_fail.value(),
                ban_ttl_seconds=self.spin_ban_ttl.value(),
            )
            n = self.proxy_manager.load_file(self.proxies_file.text().strip())
        except ProxyManagerError as e:
            QMessageBox.critical(self, "Proxies", str(e))
            return
        self._fill_proxy_table(self.proxy_manager.summary())
        self.proxy_count.setText(f"{n} proxies cargados (formato IP:PORT:USER:PASSWORD)")

    def _fill_proxy_table(self, rows: list[dict]) -> None:
        t = self.proxy_table
        t.setRowCount(0)
        for r in rows:
            row = t.rowCount()
            t.insertRow(row)
            vals = [r["proxy"], r["state"], str(r["requests"]), str(r["successes"]),
                    str(r["failures"]), str(r["avg_latency"]), str(r["banned_remaining"])]
            for col, val in enumerate(vals):
                t.setItem(row, col, QTableWidgetItem(str(val)))

    def _proxies_check(self) -> None:
        if not self.proxy_manager or not len(self.proxy_manager):
            QMessageBox.warning(self, "Proxies", "Carga primero el fichero de proxies.")
            return
        if self.proxy_worker and self.proxy_worker.isRunning():
            return
        self.proxy_worker = ProxyCheckWorker(
            self.proxy_manager, self.check_url.text().strip(),
            self.spin_check_to.value(), self.spin_check_conc.value())
        self.proxy_worker.signals.done.connect(self._proxies_checked)
        self.proxy_worker.signals.error.connect(
            lambda e: QMessageBox.critical(self, "Verificación", e))
        self.statusBar().showMessage("Verificando proxies…")
        self.proxy_worker.start()

    def _proxies_checked(self, results) -> None:
        self._fill_proxy_table(self.proxy_manager.summary())
        ok = sum(1 for r in results if r["ok"])
        self.statusBar().showMessage(f"Verificación completada: {ok}/{len(results)} proxies OK")

    # ================= AUDITORÍA SQLi =================
    def _build_sqli_tab(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        left = QVBoxLayout()

        gb_scope = QGroupBox("Lista blanca de dominios AUTORIZADOS para la auditoría")
        sv = QVBoxLayout(gb_scope)
        self.sqli_scope = QPlainTextEdit()
        self.sqli_scope.setPlaceholderText("127.0.0.1\nlocalhost\nlab.example.com")
        self.sqli_scope.setMaximumHeight(70)
        sv.addWidget(self.sqli_scope)
        left.addWidget(gb_scope)

        gb_t = QGroupBox("Objetivo")
        tf = QFormLayout(gb_t)
        self.sqli_url = QLineEdit(); self.sqli_url.setPlaceholderText(
            "http://127.0.0.1:8000/vulnerable/product?id=1")
        tf.addRow("URL objetivo:", self.sqli_url)
        self.sqli_params = QLineEdit(); self.sqli_params.setPlaceholderText(
            "vacío = autodetectar parámetros GET (o lista separada por comas)")
        tf.addRow("Parámetros:", self.sqli_params)
        tech_row = QHBoxLayout()
        self.chk_error = QCheckBox("Errores de BD (no destructiva)")
        self.chk_error.setChecked(True)
        self.chk_bool = QCheckBox("Comparación booleana 1=1 / 1=2 (no destructiva)")
        self.chk_bool.setChecked(True)
        tech_row.addWidget(self.chk_error)
        tech_row.addWidget(self.chk_bool)
        tf.addRow("Técnicas:", tech_row)
        self.spin_audit_to = QDoubleSpinBox(); self.spin_audit_to.setRange(1, 60)
        self.spin_audit_to.setValue(10)
        tf.addRow("Timeout HTTP (s):", self.spin_audit_to)
        left.addWidget(gb_t)

        ab = QHBoxLayout()
        b_run = QPushButton("Ejecutar auditoría (no destructiva)")
        b_run.clicked.connect(self._sqli_audit)
        b_lab = QPushButton("Iniciar laboratorio local")
        b_lab.clicked.connect(self._sqli_start_lab)
        b_report = QPushButton("Generar informe")
        b_report.clicked.connect(self._sqli_report)
        ab.addWidget(b_run); ab.addWidget(b_lab); ab.addWidget(b_report)
        left.addLayout(ab)

        gb_l = QGroupBox("Registro de la auditoría")
        lv = QVBoxLayout(gb_l)
        self.sqli_log = QPlainTextEdit(); self.sqli_log.setReadOnly(True)
        lv.addWidget(self.sqli_log)
        left.addWidget(gb_l, 1)

        right = QVBoxLayout()
        gb_f2 = QGroupBox("Hallazgos (clasificados por nivel de evidencia)")
        fv = QVBoxLayout(gb_f2)
        self.findings_table = QTableWidget()
        _init_table(self.findings_table,
                    ["Evidencia", "URL", "Parámetro", "Técnica", "Motor BD", "Detalle"])
        fv.addWidget(self.findings_table)
        right.addWidget(gb_f2, 1)

        h.addLayout(left, 2)
        h.addLayout(right, 3)
        return w

    def _sqli_start_lab(self) -> None:
        try:
            from ..sqli.lab.lab_server import start_lab
            if getattr(self, "_lab", None) is None:
                self._lab = start_lab()
                self.sqli_scope.setPlainText("127.0.0.1")
                self.sqli_url.setText(f"{self._lab.base_url}/vulnerable/product?id=1")
                self.sqli_log.appendPlainText(
                    f"[lab] Laboratorio local iniciado en {self._lab.base_url} "
                    "(datos ficticios, solo localhost)")
            else:
                self.sqli_log.appendPlainText(f"[lab] Ya en ejecución: {self._lab.base_url}")
        except Exception as e:
            QMessageBox.critical(self, "Laboratorio", f"No se pudo iniciar: {e}")

    def _sqli_audit(self) -> None:
        if self.audit_worker and self.audit_worker.isRunning():
            QMessageBox.warning(self, "Auditoría", "Ya hay una auditoría en curso.")
            return
        scope = [l.strip() for l in self.sqli_scope.toPlainText().splitlines() if l.strip()]
        url = self.sqli_url.text().strip()
        if not scope or not url:
            QMessageBox.warning(self, "Faltan datos",
                                "Define la lista blanca y la URL objetivo.")
            return
        from ..sqli.scope import ScopeGuard
        if not ScopeGuard(scope).is_allowed(url):
            QMessageBox.critical(
                self, "Fuera de alcance",
                "El objetivo NO está en la lista blanca autorizada.\n"
                "La auditoría está bloqueada por seguridad.")
            return
        techniques = tuple(t for t, chk in
                           (("error", self.chk_error), ("boolean", self.chk_bool))
                           if chk.isChecked())
        if not techniques:
            QMessageBox.warning(self, "Técnicas", "Selecciona al menos una técnica.")
            return
        params = [p.strip() for p in self.sqli_params.text().split(",") if p.strip()] or None
        self.audit_worker = AuditWorker(
            [url], scope, techniques, self.spin_audit_to.value(), db=self.db,
            user_agent=self.cfg.sqli.user_agent,
            max_requests=self.cfg.sqli.max_requests_per_audit)
        aw = self.audit_worker.signals
        aw.log.connect(self.sqli_log.appendPlainText)
        aw.done.connect(self._sqli_done)
        aw.error.connect(lambda e: (self.sqli_log.appendPlainText(f"[ERROR] {e}")))
        self.sqli_log.appendPlainText(f"[auditoría] iniciando: {url} · técnicas={techniques}")
        self.audit_worker.start()

    def _sqli_done(self, findings) -> None:
        t = self.findings_table
        t.setRowCount(0)
        for f in findings or []:
            row = t.rowCount()
            t.insertRow(row)
            vals = [f.evidence, f.url, f.param, f.technique, f.dbms or "-", f.details]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if col == 0:
                    if f.evidence == "CONFIRMED":
                        item.setForeground(Qt.red)
                    elif f.evidence == "LIKELY":
                        item.setForeground(Qt.darkYellow)
                t.setItem(row, col, item)
        self.sqli_log.appendPlainText(f"[auditoría] completada: {len(findings or [])} hallazgo(s)")
        self.refresh_dashboard()

    def _sqli_report(self) -> None:
        raw = self.db.list_findings()
        from ..models import Finding
        findings = [
            Finding(url=r["url"], param=r["param"], technique=r["technique"], dbms=r["dbms"],
                    evidence=r["evidence"], evidence_level=0, details=r["details"],
                    request_snapshot=r.get("request_json") or {},
                    evidence_snippets=r.get("snippets") or [],
                    remediation=r.get("remediation") or [], timestamp=r.get("ts", ""))
            for r in raw
        ]
        scope = [l.strip() for l in self.sqli_scope.toPlainText().splitlines() if l.strip()] or \
            self.cfg.sqli.allowed_domains
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json = f"reports/audit_report_{ts}.json"
        out_md = f"reports/audit_report_{ts}.md"
        generate_report(findings, scope, out_json=out_json, out_md=out_md,
                        meta={"targets": len({f.url for f in findings}) or 1,
                              "origen": "GUI"})
        self.sqli_log.appendPlainText(f"[informe] generado: {out_md} y {out_json}")
        QMessageBox.information(self, "Informe", f"Informe generado:\n{out_md}\n{out_json}")

    # ================= cierre =================
    def closeEvent(self, event) -> None:  # noqa: N802
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.stop()
            self.search_worker.wait(5000)
        if getattr(self, "_lab", None) is not None:
            try:
                self._lab.stop()
            except Exception:
                pass
        try:
            self.db.close()
        except Exception:
            pass
        super().closeEvent(event)
