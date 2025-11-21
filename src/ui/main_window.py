import sys
import os
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QPushButton, QFrame, QStackedWidget, QFileDialog)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
import qtawesome as qta

from src.ui.styles import Theme
from src.core.parser import ManifestParser

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dependency-Sentry")
        self.resize(1200, 800)
        self.setAcceptDrops(True)
        
        self.parser = ManifestParser()
        self.is_dark = True
        
        # Setup UI
        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        # Main Layout: Sidebar (Left) + Content (Right)
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
        title.setStyleSheet("font-weight: 900; font-size: 16px; letter-spacing: 2px;")
        sidebar_layout.addWidget(title)
        sidebar_layout.addSpacing(30)
        
        # Nav Buttons
        self.btn_graph = self.create_nav_btn("  AUDITOR", "fa5s.project-diagram")
        self.btn_graph.setChecked(True)
        self.btn_settings = self.create_nav_btn("  SETTINGS", "fa5s.cog")
        
        sidebar_layout.addWidget(self.btn_graph)
        sidebar_layout.addWidget(self.btn_settings)
        sidebar_layout.addStretch()
        
        # Theme Toggle
        self.btn_theme = QPushButton("  LIGHT MODE")
        self.btn_theme.setObjectName("theme_btn")
        self.btn_theme.setIcon(qta.icon('fa5s.sun', color='#666'))
        self.btn_theme.clicked.connect(self.toggle_theme)
        self.btn_theme.setStyleSheet("""
            QPushButton { border: none; color: #666; font-weight: bold; padding: 10px; }
            QPushButton:hover { color: #FFF; }
        """)
        sidebar_layout.addWidget(self.btn_theme)
        
        # 2. Content Stack
        self.stack = QStackedWidget()
        
        # Page 1: Auditor (The Graph View)
        self.page_audit = QWidget()
        audit_layout = QVBoxLayout(self.page_audit)
        audit_layout.setContentsMargins(40, 40, 40, 40)
        
        self.drop_zone = QLabel("DRAG REQUIREMENTS.TXT HERE\n\n[ OR CLICK TO BROWSE ]")
        self.drop_zone.setObjectName("drop_zone")
        self.drop_zone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_zone.setCursor(Qt.CursorShape.PointingHandCursor)
        # Enable click to browse (Subclassing logic simulated here for brevity)
        self.drop_zone.mousePressEvent = self.browse_file
        
        audit_layout.addWidget(self.drop_zone)
        self.stack.addWidget(self.page_audit)
        
        # Add to main layout
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack)

    def create_nav_btn(self, text, icon_name):
        btn = QPushButton(text)
        btn.setProperty("class", "nav_btn")
        btn.setIcon(qta.icon(icon_name, color='#666'))
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        return btn

    def apply_theme(self):
        if self.is_dark:
            self.setStyleSheet(Theme.DARK_STYLES)
            self.btn_theme.setText("  LIGHT MODE")
            self.btn_theme.setIcon(qta.icon('fa5s.sun', color='#666'))
        else:
            self.setStyleSheet(Theme.LIGHT_STYLES)
            self.btn_theme.setText("  DARK MODE")
            self.btn_theme.setIcon(qta.icon('fa5s.moon', color='#666'))

    def toggle_theme(self):
        self.is_dark = not self.is_dark
        self.apply_theme()

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
        print(f"[*] Processing file: {file_path}")
        packages = self.parser.parse(file_path)
        print(f"[*] Found {len(packages)} packages: {packages}")
        self.drop_zone.setText(f"LOADED: {os.path.basename(file_path)}\n\nFound {len(packages)} packages.\nCheck Console for details.")