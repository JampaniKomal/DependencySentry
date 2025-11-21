import sys
from PyQt6.QtWidgets import QApplication
from src.ui.main_window import MainWindow

def main():
    # High DPI scaling for modern screens
    sys.argv += ['-platform', 'windows:darkmode=2']
    sys.argv += ['-style', 'Fusion']
    
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()