"""The desktop window, headless."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def window():
    from dependency_sentry.ui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    w = MainWindow()
    yield w
    w.close()
    app.processEvents()


def test_report_fills_the_tree_and_details(window, report):
    window.show_report(report)
    top = [window.tree.topLevelItem(i).text(0) for i in range(window.tree.topLevelItemCount())]
    assert top == ["Django", "requests"]
    django = window.tree.topLevelItem(0)
    assert django.text(2) == "2" and django.text(3) == "CRITICAL" and "upgrade to" in django.text(4)
    assert sorted(django.child(i).text(0) for i in range(django.childCount())) == ["asgiref", "pytz", "sqlparse"]
    window.show_details(django)
    assert "GHSA-bbbb" in window.details.toHtml() and "Fixed in 3.2.13" in window.details.toPlainText()
    assert window.btn_sbom.isEnabled()
    assert "2 vulnerable" in window.summary.text()


def test_settings_page_drives_the_audit_settings(window):
    window.mode_box.setCurrentText("approximate")
    window.days_box.setValue(365)
    s = window.settings()
    assert s.mode == "approximate" and s.abandoned_after_days == 365
