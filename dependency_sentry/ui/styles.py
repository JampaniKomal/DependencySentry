class Theme:
    # Shared Button Style (Matches QuishGuard)
    SIDEBAR_BTN_STYLE = """
    QPushButton {
        background-color: transparent;
        color: #666666;
        text-align: left;
        padding-left: 20px; 
        border: none;
        border-left: 3px solid transparent;
        font-weight: bold;
        font-size: 12px;
        height: 45px;
        font-family: 'Segoe UI', sans-serif;
    }
    QPushButton:hover {
        color: #FFFFFF;
        background-color: #111111;
        border-left: 3px solid #FFFFFF;
    }
    QPushButton:checked {
        color: #FFFFFF;
        background-color: #1A1A1A;
        border-left: 3px solid #FFFFFF;
    }
    """

    DARK_STYLES = SIDEBAR_BTN_STYLE + """
    QMainWindow {
        background-color: #050505;
    }
    
    /* Sidebar with Gradient */
    QFrame#sidebar {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #000000, stop:1 #0F0F0F);
        border-right: 1px solid #222222;
    }
    
    /* Drop Zone - Dashed High Contrast */
    QLabel#drop_zone {
        background-color: #0A0A0A;
        border: 2px dashed #333333;
        border-radius: 8px;
        color: #555555;
        font-size: 14px;
        font-weight: bold;
    }
    QLabel#drop_zone:hover {
        border-color: #FFFFFF;
        color: #FFFFFF;
        background-color: #111111;
    }
    
    /* Console Styling */
    QTextEdit#console {
        background-color: #080808;
        border: 1px solid #222222;
        color: #00FF00;  /* Hacker Green Text */
        font-family: Consolas, 'Courier New', Monospace;
        font-size: 12px;
        padding: 10px;
    }
    
    QSplitter::handle {
        background-color: #222222;
    }
    QSplitter::handle:hover {
        background-color: #FFFFFF; 
    }
    """

    LIGHT_STYLES = SIDEBAR_BTN_STYLE.replace("#666666", "#888888").replace("#FFFFFF", "#000000").replace("#111111", "#EEEEEE").replace("#1A1A1A", "#DDDDDD") + """
    QMainWindow {
        background-color: #FFFFFF;
    }
    
    QFrame#sidebar {
        background-color: #F9F9F9;
        border-right: 1px solid #DDDDDD;
    }
    
    QLabel#drop_zone {
        background-color: #FAFAFA;
        border: 2px dashed #CCCCCC;
        border-radius: 8px;
        color: #888888;
        font-size: 14px;
    }
    
    QTextEdit#console {
        background-color: #FFFFFF;
        border: 1px solid #CCCCCC;
        color: #333333;
        font-family: Consolas, Monospace;
    }
    
    QSplitter::handle {
        background-color: #DDDDDD;
    }
    """