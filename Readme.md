ReMap/
│
├── src/
│   ├── __init__.py
│   ├── main.py                     # Entry point of the application
│   │
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── main_window.py          # Main GUI window
│   │   ├── target_input_frame.py   # Target input section
│   │   ├── scan_options_frame.py   # Scan preset options
│   │   ├── results_frame.py        # Results display area
│   │   ├── settings_frame.py       # Settings page/dialog
│   │   ├── progress_dialog.py      # Scan progress indicator
│   │   └── styles.py               # GUI styling and themes
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py              # Main scanning logic
│   │   ├── nmap_wrapper.py         # Nmap command execution
│   │   ├── target_parser.py        # Parse IP addresses and files
│   │   ├── xml_parser.py           # Parse Nmap XML output
│   │   └── rate_limiter.py         # Rate limiting functionality
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── security_analyzer.py    # Main analysis coordinator
│   │   ├── tls_analyzer.py         # TLS version checks
│   │   ├── ssl_analyzer.py         # SSL certificate and version checks
│   │   ├── smb_analyzer.py         # SMB signing checks
│   │   └── web_detector.py         # Web service detection
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── report_generator.py     # Generate formatted reports
│   │   ├── xml_loader.py           # Load existing XML reports
│   │   └── export_manager.py       # Handle report exports
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── config.py               # Configuration management
│   │   ├── logger.py               # Logging functionality
│   │   ├── validators.py           # Input validation
│   │   └── file_handler.py         # File operations
│   │
│   └── models/
│       ├── __init__.py
│       ├── scan_result.py          # Data models for scan results
│       ├── target.py               # Target representation
│       └── settings.py             # Settings data model
│
├── resources/
│   ├── icons/                      # Application icons
│   ├── templates/                  # Report templates
│   └── config/
│       └── default_settings.json   # Default configuration
│
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_analyzers.py
│   ├── test_parsers.py
│   └── test_gui.py
│
├── docs/
│   ├── user_manual.md
│   ├── api_documentation.md
│   └── development_notes.md
│
├── build/
│   ├── build_script.py             # PyInstaller build script
│   └── requirements_build.txt      # Build-specific dependencies
│
├── requirements.txt                # Project dependencies
├── setup.py                       # Package setup
├── README.md                      # Project overview
├── LICENSE                        # License file
└── .gitignore                     # Git ignore rules