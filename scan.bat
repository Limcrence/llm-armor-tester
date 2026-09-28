@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   LLM Armor Tester - One Click Wizard
echo ============================================
python -m armor_tester wizard
echo.
pause
