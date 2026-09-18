@echo off
cd /d "%~dp0"
python -m pip install -q pyinstaller paramiko
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name "NUCLEI-INSTALLER-v1.0.0" --add-data "payload;payload" --hidden-import paramiko --collect-submodules paramiko nuclei_setup.py
if errorlevel 1 (
  echo BUILD FAILED
  pause
  exit /b 1
)
copy /Y "dist\NUCLEI-INSTALLER-v1.0.0.exe" "."
echo.
echo Built: %cd%\NUCLEI-INSTALLER-v1.0.0.exe
pause
