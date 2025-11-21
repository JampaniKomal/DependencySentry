import sys
import os
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QFrame, QStackedWidget, QFileDialog,
                             QSplitter, QTextEdit, QApplication)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
import qtawesome as qta

from src.ui.styles import Theme
from src.core.parser import ManifestParser

# --- CUSTOM CONSOLE WIDGET (From QuishGuard) ---
class OverlayConsole(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("console")
        self.setReadOnly(True)

# --- MAIN WINDOW ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dependency-Sentry | SBOM Auditor")
        self.resize(1200, 800)
        self.setAcceptDrops(True)
        
        self.parser = ManifestParser()
        self.is_dark = True
        
        # Icons
        self.icon_audit = qta.icon('fa5s.project-diagram', color='#666')
        self.icon_settings = qta.icon('fa5s.cog', color='#666')
        self.icon_moon = qta.icon('fa5s.moon', color='#666')
        self.icon_sun = qta.icon('fa5s.sun', color='#666')
        
        self.init_ui()
        self.apply_theme()
        self.log_message("[*] Dependency-Sentry Initialized.")

    def init_ui(self):
        # Main Container
        container = QWidget()
        self.setCentralWidget(container)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # 1. Sidebar
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        
        # Title
        title = QLabel("DEPENDENCY\nSENTRY")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-weight: 900; font-size: 16px; letter-spacing: 2px; color: #888;")
        sidebar_layout.addWidget(title)
        sidebar_layout.addSpacing(30)
        
        # Nav Buttons
        self.btn_graph = self.create_nav_btn("  AUDITOR", self.icon_audit)
        self.btn_graph.setChecked(True)
        self.btn_settings = self.create_nav_btn("  SETTINGS", self.icon_settings)
        
        sidebar_layout.addWidget(self.btn_graph)
        sidebar_layout.addWidget(self.btn_settings)
        sidebar_layout.addStretch()
        
        # Theme Toggle
        self.btn_theme = QPushButton("  LIGHT MODE")
        self.btn_theme.setIcon(self.icon_sun)
        self.btn_theme.clicked.connect(self.toggle_theme)
        self.btn_theme.setStyleSheet("""
            QPushButton { border: none; color: #666; font-weight: bold; padding: 10px; }
            QPushButton:hover { color: #FFF; }
        """)
        sidebar_layout.addWidget(self.btn_theme)
        
        # 2. Content Area (Stack)
        self.stack = QStackedWidget()
        
        # --- Page 1: Auditor ---
        self.page_audit = QWidget()
        audit_layout = QVBoxLayout(self.page_audit)
        audit_layout.setContentsMargins(20, 20, 20, 20)
        
        # The Splitter (Drop Zone Top / Console Bottom)
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.setHandleWidth(2)
        
        # Drop Zone
        self.drop_zone = QLabel("DRAG REQUIREMENTS.TXT HERE\n\n[ OR CLICK TO BROWSE ]")
        self.drop_zone.setObjectName("drop_zone")
        self.drop_zone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_zone.setCursor(Qt.CursorShape.PointingHandCursor)
        self.drop_zone.mousePressEvent = self.browse_file
        self.splitter.addWidget(self.drop_zone)
        
        # Console
        self.console = OverlayConsole()
        self.splitter.addWidget(self.console)
        
        # Set Initial Sizes (70% Top, 30% Bottom)
        self.splitter.setSizes([500, 200])
        
        audit_layout.addWidget(self.splitter)
        self.stack.addWidget(self.page_audit)
        
        # Add to Main Layout
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack)

    def create_nav_btn(self, text, icon):
        btn = QPushButton(text)
        btn.setIcon(icon)
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        return btn

    def apply_theme(self):
        if self.is_dark:
            self.setStyleSheet(Theme.DARK_STYLES)
            self.btn_theme.setText("  LIGHT MODE")
            self.btn_theme.setIcon(self.icon_sun)
        else:
            self.setStyleSheet(Theme.LIGHT_STYLES)
            self.btn_theme.setText("  DARK MODE")
            self.btn_theme.setIcon(self.icon_moon)

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

    def log_message(self, message):
        """Appends text to the visible console"""
        self.console.append(message)
        # Auto scroll to bottom
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    # --- Logic ---
    def browse_file(self, event):
        fname, _ = QFileDialog.getOpenFileName(self, 'Open Manifest', '', 'Text Files (*.txt *.json)')
        if fname:
            self.process_file(fname)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.process_file(files[0])

    def process_file(self, file_path):
        self.console.clear()
        self.log_message(f"[*] Processing file: {file_path}")
        
        try:
            packages = self.parser.parse(file_path)
            if not packages:
                self.log_message("[!] No valid packages found or file is empty.")
                return
                
            self.log_message(f"[*] Found {len(packages)} direct dependencies.")
            for pkg in packages:
                self.log_message(f"    - {pkg}")
                
            self.drop_zone.setText(f"LOADED: {os.path.basename(file_path)}\n\nReady to Audit.")
            
        except Exception as e:
            self.log_message(f"[!] Critical Error: {str(e)}")