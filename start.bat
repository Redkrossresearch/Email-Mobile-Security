@echo off
echo ============================================
echo   CyberShield - Killing old processes...
echo ============================================
taskkill /F /IM python.exe 2>nul
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo.
echo ============================================
echo   CyberShield Zero Trust Platform v6.0
echo   Single-port deployment (Frontend+Backend)
echo ============================================
echo.

cd /d C:\Users\Bhoomi\Downloads\Forntend1\Forntend1\backend

echo Clearing Python cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /S /Q "%%d" 2>nul
echo.

if not exist "..\react_app\index.html" (
    echo WARNING: React build not found!
    echo Run: cd ..\email-mobile-security\frontend ^&^& npm run build
    echo Then copy dist\ to ..\react_app\
    echo.
)

echo Starting server on http://localhost:5000 ...
echo.
python -B app.py
