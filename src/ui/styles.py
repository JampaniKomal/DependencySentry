class Theme:
    # --- DARK MODE (Default) ---
    DARK_STYLES = """
    QMainWindow {
        background-color: #050505;
    }
    
    /* Sidebar Styling */
    QFrame#sidebar {
        background-color: #000000;
        border-right: 1px solid #333333;
    }
    
    /* Navigation Buttons */
    QPushButton.nav_btn {
        background-color: transparent;
        color: #666666;
        text-align: left;
        padding: 15px 20px;
        border: none;
        border-left: 2px solid transparent;
        font-weight: bold;
        font-size: 12px;
        font-family: 'Segoe UI', sans-serif;
    }
    QPushButton.nav_btn:hover {
        color: #FFFFFF;
        background-color: #111111;
        border-left: 2px solid #FFFFFF;
    }
    QPushButton.nav_btn:checked {
        color: #FFFFFF;
        background-color: #1A1A1A;
        border-left: 2px solid #FFFFFF;
    }

    /* Drop Zone */
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
    
    /* General Text */
    QLabel { color: #E0E0E0; }
    """

    # --- LIGHT MODE ---
    LIGHT_STYLES = """
    QMainWindow {
        background-color: #FFFFFF;
    }
    
    QFrame#sidebar {
        background-color: #F5F5F5;
        border-right: 1px solid #DDDDDD;
    }
    
    QPushButton.nav_btn {
        background-color: transparent;
        color: #999999;
        text-align: left;
        padding: 15px 20px;
        border: none;
        border-left: 2px solid transparent;
        font-weight: bold;
        font-size: 12px;
    }
    QPushButton.nav_btn:hover {
        color: #000000;
        background-color: #EAEAEA;
        border-left: 2px solid #000000;
    }
    
    QLabel#drop_zone {
        background-color: #FAFAFA;
        border: 2px dashed #CCCCCC;
        border-radius: 8px;
        color: #888888;
        font-size: 14px;
    }
    QLabel#drop_zone:hover {
        border-color: #000000;
        color: #000000;
        background-color: #F0F0F0;
    }
    
    QLabel { color: #111111; }
    """