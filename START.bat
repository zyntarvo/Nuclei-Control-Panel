@echo off
cd /d "%~dp0"
python -m pip install -q paramiko
python nuclei_setup.py
if errorlevel 1 pause
