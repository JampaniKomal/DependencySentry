import json
import os

import qtawesome as qta
from PyQt6.QtCore import QSettings, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QDragEnterEvent, QDropEvent
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dependency_sentry import __version__
from dependency_sentry.core import audit, export
from dependency_sentry.ui.styles import Theme

SEVERITY_COLOURS = {
    "CRITICAL": "#ff3b30",
    "HIGH": "#ff6b3d",
    "MODERATE": "#ffb020",
    "LOW": "#c8c840",
    "UNKNOWN": "#c8c840",
}


class OverlayConsole(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("console")
        self.setReadOnly(True)


class AuditWorker(QThread):
    """Runs the audit off the GUI thread: resolution and OSV lookups make network calls."""

    log = pyqtSignal(str)
    done = pyqtSignal(object)  # AuditReport
    failed = pyqtSignal(str)

    def __init__(self, path, settings, parent=None):
        super().__init__(parent)
        self.path, self.settings = path, settings

    def run(self):
        try:
            self.done.emit(audit.run(self.path, self.settings, self.log.emit))
        except Exception as exc:  # report, never crash the window
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Dependency-Sentry {__version__} | SBOM Auditor")
        self.resize(1250, 820)
        self.setAcceptDrops(True)
        self.worker = None
        self.report = None
        self.is_dark = True
        self.prefs = QSettings("JampaniKomal", "DependencySentry")

        self.icon_audit = qta.icon("fa5s.project-diagram", color="#666")
        self.icon_settings = qta.icon("fa5s.cog", color="#666")
        self.icon_moon = qta.icon("fa5s.moon", color="#666")
        self.icon_sun = qta.icon("fa5s.sun", color="#666")

        self.init_ui()
        self.apply_theme()
        self.log_message("[*] Dependency-Sentry initialised. Drop a requirements.txt or pyproject.toml.")

    # --- layout -------------------------------------------------------------
    def init_ui(self):
        container = QWidget()
        self.setCentralWidget(container)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(200)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(0, 20, 0, 20)
        title = QLabel("DEPENDENCY\nSENTRY")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-weight: 900; font-size: 16px; letter-spacing: 2px; color: #888;")
        side.addWidget(title)
        side.addSpacing(30)
        self.btn_audit = self.create_nav_btn("  AUDITOR", self.icon_audit)
        self.btn_audit.setChecked(True)
        self.btn_audit.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_settings = self.create_nav_btn("  SETTINGS", self.icon_settings)
        self.btn_settings.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        side.addWidget(self.btn_audit)
        side.addWidget(self.btn_settings)
        side.addStretch()
        self.btn_theme = QPushButton("  LIGHT MODE")
        self.btn_theme.clicked.connect(self.toggle_theme)
        self.btn_theme.setStyleSheet(
            "QPushButton { border: none; color: #666; font-weight: bold; padding: 10px; }"
            "QPushButton:hover { color: #FFF; }"
        )
        side.addWidget(self.btn_theme)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.build_audit_page())
        self.stack.addWidget(self.build_settings_page())
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack)

    def build_audit_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(20, 20, 20, 20)

        top = QHBoxLayout()
        self.drop_zone = QLabel("DRAG requirements.txt OR pyproject.toml HERE\n\n[ OR CLICK TO BROWSE ]")
        self.drop_zone.setObjectName("drop_zone")
        self.drop_zone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_zone.setCursor(Qt.CursorShape.PointingHandCursor)
        self.drop_zone.setMinimumHeight(110)
        self.drop_zone.mousePressEvent = self.browse_file
        top.addWidget(self.drop_zone, stretch=1)
        buttons = QVBoxLayout()
        self.btn_sbom = QPushButton(" Export SBOM (CycloneDX)")
        self.btn_sbom.setIcon(qta.icon("fa5s.file-export", color="#888"))
        self.btn_sbom.clicked.connect(self.export_sbom)
        self.btn_report = QPushButton(" Save report (JSON)")
        self.btn_report.setIcon(qta.icon("fa5s.save", color="#888"))
        self.btn_report.clicked.connect(self.save_json)
        for b in (self.btn_sbom, self.btn_report):
            b.setEnabled(False)
            b.setStyleSheet("QPushButton { padding: 8px 14px; text-align: left; border: 1px solid #333; }")
            buttons.addWidget(b)
        buttons.addStretch()
        top.addLayout(buttons)
        outer.addLayout(top)

        self.summary = QLabel("")
        self.summary.setStyleSheet("font-weight: bold; padding: 8px 2px; color: #9aa0a6;")
        outer.addWidget(self.summary)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Package", "Version", "Advisories", "Worst", "Fix / note"])
        self.tree.setColumnWidth(0, 230)
        self.tree.currentItemChanged.connect(self.show_details)
        split.addWidget(self.tree)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(True)
        split.addWidget(self.details)
        split.setSizes([700, 450])

        vertical = QSplitter(Qt.Orientation.Vertical)
        vertical.addWidget(split)
        self.console = OverlayConsole()
        vertical.addWidget(self.console)
        vertical.setSizes([520, 160])
        outer.addWidget(vertical, stretch=1)
        return page

    def build_settings_page(self):
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(40, 40, 40, 40)
        heading = QLabel("SETTINGS")
        heading.setStyleSheet("font-size: 22px; font-weight: bold; color: #888;")
        form.addRow(heading)
        self.mode_box = QComboBox()
        self.mode_box.addItems(["exact", "approximate"])
        self.mode_box.setCurrentText(self.prefs.value("mode", "exact"))
        self.mode_box.setToolTip(
            "exact: pip's resolver picks the versions that would really be installed (dry run, wheels only).\n"
            "approximate: walk PyPI metadata without pip (newest release that satisfies each specifier)."
        )
        form.addRow("Version resolution", self.mode_box)
        self.days_box = QSpinBox()
        self.days_box.setRange(0, 3650)
        self.days_box.setValue(int(self.prefs.value("abandoned_after_days", 730)))
        self.days_box.setSuffix(" days (0 = off)")
        form.addRow("Flag packages with no release for", self.days_box)
        note = QLabel(
            "Exact resolution runs `pip install --dry-run --only-binary=:all:` with this app's Python:\n"
            "nothing is installed and no package code is executed. Versions are those pip would pick here."
        )
        note.setStyleSheet("color: #888;")
        form.addRow(note)
        for w in (self.mode_box, self.days_box):
            w.setMinimumWidth(200)
        self.mode_box.currentTextChanged.connect(lambda v: self.prefs.setValue("mode", v))
        self.days_box.valueChanged.connect(lambda v: self.prefs.setValue("abandoned_after_days", v))
        return page

    def create_nav_btn(self, text, icon):
        btn = QPushButton(text)
        btn.setIcon(icon)
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        return btn

    def apply_theme(self):
        self.setStyleSheet(Theme.DARK_STYLES if self.is_dark else Theme.LIGHT_STYLES)
        self.btn_theme.setText("  LIGHT MODE" if self.is_dark else "  DARK MODE")
        self.btn_theme.setIcon(self.icon_sun if self.is_dark else self.icon_moon)

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def log_message(self, message):
        self.console.append(message)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    # --- input ---------------------------------------------------------------
    def browse_file(self, event):
        fname, _ = QFileDialog.getOpenFileName(
            self, "Open manifest", "", "Python manifests (*.txt *.in pyproject.toml);;All files (*)"
        )
        if fname:
            self.process_file(fname)

    def dragEnterEvent(self, event: QDragEnterEvent):
        event.accept() if event.mimeData().hasUrls() else event.ignore()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.process_file(files[0])

    def settings(self):
        return audit.Settings(mode=self.mode_box.currentText(), abandoned_after_days=self.days_box.value())

    def process_file(self, file_path):
        if self.worker is not None and self.worker.isRunning():
            self.log_message("[!] An audit is already running.")
            return
        self.console.clear()
        self.tree.clear()
        self.details.clear()
        self.summary.setText("")
        self.log_message(f"[*] Auditing {file_path}")
        self.drop_zone.setText(f"LOADED: {os.path.basename(file_path)}\n\nAuditing...")
        self.drop_zone.setEnabled(False)
        self.worker = AuditWorker(file_path, self.settings())
        self.worker.log.connect(self.log_message)
        self.worker.done.connect(self.show_report)
        self.worker.failed.connect(self.show_failure)
        self.worker.start()

    # --- results -------------------------------------------------------------
    def show_failure(self, message):
        self.drop_zone.setEnabled(True)
        self.drop_zone.setText("AUDIT FAILED\n\n[ DROP OR CLICK TO TRY AGAIN ]")
        self.log_message(f"[!] {message}")

    def show_report(self, report):
        self.report = report
        self.drop_zone.setEnabled(True)
        g = report.graph
        name = report.manifest.path.name
        self.drop_zone.setText(f"AUDITED: {name}\n\n[ DROP OR CLICK FOR ANOTHER ]")
        self.summary.setText(
            f"{len(g.packages)} packages ({g.mode})  |  {len(report.vulnerable)} vulnerable"
            f"  |  {sum(len(v) for v in report.advisories.values())} advisories  |  {len(report.abandoned)} stale"
        )
        self.tree.clear()

        def add(parent, key, path):
            p = g.packages[key]
            advisories = report.advisories.get(key) or []
            worst = report.worst(key) or ""
            fixes = sorted({f for a in advisories if (f := a.fixed_after(p.version))})
            note = f"upgrade to {fixes[-1]}" if fixes else ""
            if key in report.abandoned:
                note = (note + "; " if note else "") + f"no release since {report.abandoned[key]:%Y-%m-%d}"
            item = QTreeWidgetItem([p.name, p.version, str(len(advisories) or ""), worst, note])
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            if worst:
                for col in range(5):
                    item.setForeground(col, QBrush(QColor(SEVERITY_COLOURS[worst])))
            if parent is None:
                self.tree.addTopLevelItem(item)
            else:
                parent.addChild(item)
            if key not in path:  # guard against dependency cycles
                for child in p.requires:
                    add(item, child, path | {key})

        for root in sorted(g.roots(), key=lambda p: p.key):
            add(None, root.key, frozenset())
        self.tree.expandToDepth(0)
        for b in (self.btn_sbom, self.btn_report):
            b.setEnabled(True)
        self.details.setHtml(
            "<p>Select a package to see its advisories.</p>" + "".join(f"<p><b>Note:</b> {n}</p>" for n in report.notes)
        )

    def show_details(self, item, _previous=None):
        if not item or not self.report:
            return
        key = item.data(0, Qt.ItemDataRole.UserRole)
        p = self.report.graph.packages[key]
        parts = [
            f"<h3>{p.name} {p.version}</h3>",
            f"<p><a href='https://pypi.org/project/{p.name}/{p.version}/'>PyPI</a>",
        ]
        if key in self.report.abandoned:
            parts.append(f" | no release since {self.report.abandoned[key]:%Y-%m-%d}")
        parts.append("</p>")
        advisories = self.report.advisories.get(key) or []
        if not advisories:
            parts.append("<p>No known vulnerabilities in OSV.dev.</p>")
        for a in advisories:
            fix = a.fixed_after(p.version)
            colour = SEVERITY_COLOURS.get(a.severity, "#aaa")
            parts.append(
                f"<p><b style='color:{colour}'>{a.severity}</b> <a href='{a.url}'>{a.id}</a>"
                f" {', '.join(a.cves)}<br>{a.summary}"
                + (f"<br><i>Fixed in {fix}</i>" if fix else "<br><i>No fixed version listed</i>")
                + "</p>"
            )
        self.details.setHtml("".join(parts))

    def _save(self, title, default, content):
        path, _ = QFileDialog.getSaveFileName(self, title, default, "JSON (*.json)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2)
            self.log_message(f"[+] Saved {path}")

    def export_sbom(self):
        if self.report:
            self._save("Export CycloneDX SBOM", "sbom.cdx.json", export.cyclonedx(self.report))

    def save_json(self):
        if self.report:
            self._save("Save audit report", "dependency-sentry-report.json", export.to_json(self.report))
