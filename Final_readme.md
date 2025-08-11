# ReMap Build Instructions

## Quick Start

### For macOS/Linux (Virtual Environment Required)

1. **Create and activate virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # macOS/Linux
   # or
   venv\Scripts\activate     # Windows
   ```

2. **Install build dependencies:**
   ```bash
   pip install -r build/requirements_build.txt
   ```

3. **Run the build script:**
   ```bash
   python build/build_script.py
   ```

4. **Select option 1 for single executable (recommended)**

### For Windows (Direct Installation)

1. **Install build dependencies:**
   ```bash
   pip install -r build/requirements_build.txt
   ```

2. **Run the build script:**
   ```bash
   python build/build_script.py
   ```

3. **Select option 1 for single EXE file (recommended)**

## Build Options

### Option 1: Single Executable File (Recommended)
- **Creates:** 
  - `dist/ReMap.exe` (~50-100MB) on Windows
  - `dist/ReMap` (~50-100MB) on macOS/Linux
- **Pros:** Single file, easy distribution
- **Cons:** Slower startup, larger file

### Option 2: Directory Package
- **Creates:** 
  - `dist/ReMap/` folder with `ReMap.exe` inside (Windows)
  - `dist/ReMap/` folder with `ReMap` inside (macOS/Linux)
- **Pros:** Faster startup, smaller individual files
- **Cons:** Multiple files to distribute

### Option 3: With Console Window
- Same as Option 1 but shows console for debugging
- Useful for troubleshooting

## Manual Build Commands

### Basic build:
```bash
pyinstaller --onefile --windowed --name=ReMap src/main.py
```

### Advanced build with resources and modules:
```bash
pyinstaller --onefile --windowed --name=ReMap \
  --add-data="resources;resources" \
  --icon="resources/icons/remap.ico" \
  --hidden-import=tkinter \
  --collect-submodules=src \
  --paths=src \
  src/main.py
```

### Using spec file:
```bash
pyinstaller build/ReMap.spec
```

## Troubleshooting

### macOS Specific Issues:

#### "Onefile mode with macOS .app bundles" Warning
- **Warning:** PyInstaller creates both an executable and .app bundle in onefile mode
- **Recommendation:** Use `--onedir` mode for better macOS compatibility
- **Current behavior:** Creates both `dist/ReMap` and `dist/ReMap.app`

#### "Failed to load Python shared library" Error on macOS
- **Cause:** PyInstaller can't find or link the Python shared library correctly
- **Solutions:**
  ```bash
  # Solution 1: Clean rebuild with explicit Python library path
  rm -rf build/ dist/ *.spec
  pyinstaller --onedir --name=ReMap \
    --collect-submodules=src \
    --paths=src \
    --python-option=-u \
    src/main.py
  
  # Solution 2: Use system Python instead of Homebrew Python
  deactivate
  /usr/bin/python3 -m venv venv_system_clean
  source venv_system_clean/bin/activate
  pip install pyinstaller pillow
  
  # Solution 3: Force static linking
  pyinstaller --onedir --name=ReMap \
    --collect-submodules=src \
    --paths=src \
    --strip \
    src/main.py
  
  # Solution 4: Use different Python installation
  which python3  # Check current Python
  /opt/homebrew/bin/python3.11 -m venv venv_311
  # or
  /usr/bin/python3 -m venv venv_usr
  ```

#### "No module named 'tkinter'" Error on macOS
- **Cause:** macOS Python installations often have broken or missing tkinter
- **Note:** You cannot install tkinter via pip (`pip install tkinter` won't work)
- **Solutions:**
  ```bash
  # Solution 1: Install python-tk via Homebrew
  brew install python-tk
  
  # Solution 2: Use system Python instead of Homebrew Python
  deactivate
  /System/Library/Frameworks/Python.framework/Versions/3.x/bin/python3 -m venv venv_system
  source venv_system/bin/activate
  pip install -r build/requirements_build.txt
  
  # Solution 3: Install Python with tkinter via Homebrew
  brew install python@3.11
  /opt/homebrew/bin/python3.11 -m venv venv_tk
  source venv_tk/bin/activate
  
  # Solution 4: If ReMap has a CLI mode, build without GUI
  pyinstaller --exclude-module=tkinter [other options]
  ```

#### "tkinter installation is broken" Warning
- **Cause:** macOS Python/tkinter compatibility issue
- **Solutions:**
  ```bash
  # Option 1: Install tkinter via Homebrew
  brew install python-tk
  
  # Option 2: Use system Python with tkinter
  deactivate
  /usr/bin/python3 -m venv venv_system
  source venv_system/bin/activate
  
  # Option 3: Skip tkinter if not needed
  pyinstaller --exclude-module=tkinter [other options]
  ```

#### "externally-managed-environment" Error
- **Solution:** Always use a virtual environment on macOS/Linux
- **Commands:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r build/requirements_build.txt
  ```

#### "Executable not found" after successful build
- **Cause:** Build completed but executable path differs on macOS/Linux
- **Solution:** Check these locations:
  ```bash
  ls -la dist/ReMap      # Single file build
  ls -la dist/ReMap/     # Directory build
  ```
- **Run executable:**
  ```bash
  ./dist/ReMap           # Single file
  ./dist/ReMap/ReMap     # Directory build
  ```

#### Permission denied when running executable
- **Solution:** Make executable file runnable
  ```bash
  chmod +x dist/ReMap
  ./dist/ReMap
  ```

### Common Issues:

#### "attempted relative import beyond top-level package" Error
- **Cause:** Code uses relative imports (like `from ..module import something`) that break when packaged
- **Common problematic imports:**
  ```python
  from ..models.settings import ScanSettings  # ❌ Breaks in PyInstaller
  from ...config import settings              # ❌ Too many levels up
  from . import module                         # ❌ Can cause issues
  ```
- **Solutions:**
  ```python
  # ✅ Fix 1: Use absolute imports
  from models.settings import ScanSettings
  
  # ✅ Fix 2: Add src to sys.path in main.py
  import sys
  sys.path.insert(0, os.path.dirname(__file__))
  
  # ✅ Fix 3: Use full module path
  import src.models.settings
  from src.models.settings import ScanSettings
  ```

#### "Module not found" errors (like `No module named 'utils'`)
- **Cause:** PyInstaller can't find local modules with relative imports
- **Solution 1:** Add missing modules to `hiddenimports` in spec file
- **Solution 2:** Use `--hidden-import=module_name`
- **Solution 3:** Add source directory to Python path: `--paths=src`
- **Solution 4:** Use `--collect-submodules=src` to include all source modules

#### Large executable size
- Enable UPX compression: install UPX and use `--upx-dir`
- Exclude unnecessary modules: `--exclude-module=matplotlib`

#### Resources not found
- Ensure resources are added: `--add-data="resources;resources"`
- Check file paths in code use `resource_path()` helper

#### Import errors at runtime
- Check all dependencies are included
- Test with `--onedir` first, then `--onefile`

#### Antivirus false positives (Windows)
- Code sign the executable
- Submit to antivirus vendors as false positive

### Debug build:
```bash
# Activate virtual environment first (macOS/Linux)
source venv/bin/activate  # Skip on Windows

python build/build_script.py
# Select option 3 for console build
# Run the executable from command line to see error messages

# macOS/Linux
./dist/ReMap

# Windows  
dist\ReMap.exe
```

## Platform-Specific Notes

### macOS Setup Requirements

1. **Virtual Environment is Mandatory:**
   - macOS Python installations are "externally managed" 
   - Always create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Build Output Differences:**
   - Single file builds create: `dist/ReMap` (executable) and `dist/ReMap.app` (app bundle)
   - Directory builds create: `dist/ReMap/ReMap`
   - Executables need permission: `chmod +x dist/ReMap`
   - **Recommended:** Use `--onedir` instead of `--onefile` for better macOS compatibility

3. **NSIS Installer Not Available:**
   - NSIS is Windows-only
   - Use directory build or create .dmg manually on macOS

### Linux Setup Requirements

1. **Virtual Environment Recommended:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Additional Dependencies May Be Needed:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3-dev python3-pip

   # RedHat/CentOS
   sudo yum install python3-devel python3-pip
   ```

### Windows Setup

1. **Direct Installation Usually Works:**
   - Can install dependencies system-wide
   - Virtual environment still recommended for isolation

## Creating Windows Installer

1. **Install NSIS:** Download from https://nsis.sourceforge.io/
2. **Run:** `python build/build_script.py`
3. **Select option 4** or build EXE first then option 4

## Distribution Checklist

- [ ] Build tested on clean Windows machine
- [ ] All features working in built executable
- [ ] Antivirus scan passed
- [ ] File size acceptable (<100MB preferred)
- [ ] Installer created and tested
- [ ] Documentation updated
- [ ] Version number updated

## ✅ Successful Build Example (macOS)

Here's the complete working process for macOS:

1. **Setup virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r build/requirements_build.txt
   ```

2. **Fix relative imports by adding to top of src/main.py:**
   ```python
   import sys
   import os
   
   current_dir = os.path.dirname(os.path.abspath(__file__))
   if current_dir not in sys.path:
       sys.path.insert(0, current_dir)
   ```

3. **Install tkinter support:**
   ```bash
   brew install python-tk
   ```

4. **Build successfully:**
   ```bash
   pyinstaller --onedir --name=ReMap \
     --collect-submodules=src \
     --paths=src \
     src/main.py
   ```

5. **Test the executable:**
   ```bash
   ./dist/ReMap/ReMap
   ```

## Important: Platform-Specific Builds

### ⚠️ Cross-Platform Build Limitations

**PyInstaller builds are platform-specific:**
- Building on **macOS** creates executables for **macOS only** (`ReMap`)
- Building on **Windows** creates executables for **Windows only** (`ReMap.exe`)  
- Building on **Linux** creates executables for **Linux only** (`ReMap`)

**You cannot cross-compile:** A macOS build will not run on Windows, and vice versa.

### Building for Multiple Platforms

To create executables for different platforms:

1. **For Windows:** Build on a Windows machine
2. **For macOS:** Build on a macOS machine (you've done this!)
3. **For Linux:** Build on a Linux machine

### What You Have Now

Your current build (from macOS) creates:
```
dist/ReMap/
├── ReMap          # ← Works on macOS only
└── _internal/     # ← Dependencies
```

To get `ReMap.exe` for Windows, you need to:
1. Copy your source code to a Windows machine
2. Set up the build environment there
3. Run the same build process

## Git and Version Control

### ⚠️ What NOT to Commit to Git

**Never commit these build artifacts:**
- `build/` directory (temporary build files)
- `dist/` directory (compiled executables)
- `*.spec` files (auto-generated PyInstaller specs)
- `venv/` or `venv_*/` directories (virtual environments)

### .gitignore Setup

Add this to your `.gitignore` file:
```gitignore
# Build artifacts
build/
dist/
*.spec

# Virtual environments
venv/
venv_*/
env/
.venv/

# PyInstaller
*.manifest
*.pyc
__pycache__/

# macOS
.DS_Store
*.app

# Windows
*.exe
*.msi

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log
logs/
```

### What TO Commit

**Always commit these:**
- Source code (`src/` directory)
- Build scripts (`build/build_script.py`)
- Requirements file (`build/requirements_build.txt`)
- Documentation (`Build_readme.md`, `README.md`)
- Configuration files
- Resources (`resources/` directory)

### Proper Git Workflow

```bash
# Don't add the built executable
# git add ReMap/  # ❌ DON'T DO THIS

# Instead, add only source files
git add src/
git add build/build_script.py
git add build/requirements_build.txt  
git add Build_readme.md
git add .gitignore

# Commit your changes
git commit -m "Add build system and documentation"
git push origin main
```

## Distribution Guide

### What You Get After Building

After a successful build, you'll have:
```
dist/
└── ReMap/                       # Complete application folder
    ├── ReMap                    # Main executable (ReMap.exe on Windows)
    ├── _internal/               # Dependencies and libraries
    │   ├── base_library.zip
    │   ├── Python shared libs
    │   └── All required modules
    └── [other resources]
```

### How to Distribute Your Application

#### Option 1: Folder Distribution (Recommended)
1. **Copy the entire `dist/ReMap` folder**
2. **Share/install on target machine**  
3. **Run the executable inside the folder**
   - Windows: `ReMap\ReMap.exe`
   - macOS/Linux: `./ReMap/ReMap`

#### Option 2: Compressed Archive
```bash
# Create distributable archive
cd dist
tar -czf ReMap-v1.0.tar.gz ReMap/     # macOS/Linux
zip -r ReMap-v1.0.zip ReMap/          # Windows/Cross-platform
```

#### Option 3: Windows Installer (Windows Only)
- Use build script option 4 with NSIS installed
- Creates: `ReMap-Setup-v1.0.0.exe`

### Installation Instructions for End Users

**Windows:**
1. Extract the ReMap folder anywhere (e.g., `C:\Program Files\ReMap\`)
2. Double-click `ReMap.exe` to run
3. Optionally create a desktop shortcut

**macOS:**
1. Copy ReMap folder to Applications or desired location
2. Run `./ReMap` from terminal or double-click in Finder
3. May need: `chmod +x ReMap` for permissions

**Linux:**
1. Extract ReMap folder anywhere (e.g., `/opt/ReMap/`)
2. Run `./ReMap` from terminal
3. May need: `chmod +x ReMap` for permissions

## File Locations After Build

```
dist/
├── ReMap.exe                    # Single file executable
└── ReMap/                       # Directory build
    ├── ReMap.exe
    ├── _internal/               # Dependencies
    └── resources/               # Application resources

build/
├── ReMap-Setup-v1.0.0.exe      # Windows installer
└── temp/                       # Build temporary files
```

## Quick Build Scripts

### Windows Batch File: `build/quick_build.bat`

```batch
@echo off
echo ========================================
echo ReMap Quick Build Script
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    echo Please install Python 3.7+ and add to PATH
    pause
    exit /b 1
)

echo Installing build requirements...
pip install pyinstaller pillow

echo.
echo Building ReMap executable...
echo This may take 5-10 minutes...
echo.

REM Create basic build
pyinstaller --onefile --windowed --name=ReMap --add-data="resources;resources" --hidden-import=tkinter --collect-submodules=src src/main.py

if exist "dist\ReMap.exe" (
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL!
    echo ========================================
    echo Executable location: dist\ReMap.exe
    for %%A in ("dist\ReMap.exe") do echo File size: %%~zA bytes
    echo.
    echo Testing executable...
    start "" "dist\ReMap.exe"
) else (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo Check the output above for errors
)

echo.
pause
```

### Linux/Mac Build Script: `build/quick_build.sh`

```bash
#!/bin/bash
echo "========================================"
echo "ReMap Quick Build Script"
echo "========================================"
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found"
    echo "Please install Python 3.7+"
    exit 1
fi

echo "Installing build requirements..."
pip3 install pyinstaller pillow

echo
echo "Building ReMap executable..."
echo "This may take 5-10 minutes..."
echo

# Build
pyinstaller --onefile --windowed --name=ReMap \
    --add-data="resources:resources" \
    --hidden-import=tkinter \
    --collect-submodules=src \
    src/main.py

if [ -f "dist/ReMap" ]; then
    echo
    echo "========================================"
    echo "BUILD SUCCESSFUL!"
    echo "========================================"
    echo "Executable location: dist/ReMap"
    ls -lh dist/ReMap
    echo
    echo "Testing executable..."
    ./dist/ReMap &
else
    echo
    echo "========================================"
    echo "BUILD FAILED!"
    echo "========================================"
    echo "Check the output above for errors"
fi
```

## 🚀 How to Use These Build Files

1. **Copy all files to your `build/` directory**

2. **Run the build:**
   ```bash
   # First activate virtual environment (macOS/Linux only)
   source venv/bin/activate  # macOS/Linux
   
   # Then run build script
   # Windows
   python build/build_script.py
   
   # Or quick build
   build/quick_build.bat
   
   # Linux/Mac
   chmod +x build/quick_build.sh
   ./build/quick_build.sh
   ```

3. **Select build option:**
   - Option 1: Single EXE (recommended)
   - Option 4: Create installer

4. **Find your executable:**
   - `dist/ReMap.exe` (Windows)
   - `dist/ReMap` (Linux/Mac)

5. **Run your executable:**
   ```bash
   # Windows
   dist\ReMap.exe
   
   # macOS/Linux (make executable first)
   chmod +x dist/ReMap
   ./dist/ReMap
   ```

The build script will handle all the complexity and create a fully functional standalone executable! 🎉