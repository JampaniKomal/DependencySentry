import sys


def main() -> int:
    from PyQt6.QtWidgets import QApplication

    from dependency_sentry.ui.main_window import MainWindow

    args = sys.argv + ["-style", "Fusion"]
    if sys.platform == "win32":
        args += ["-platform", "windows:darkmode=2"]
    app = QApplication(args)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
