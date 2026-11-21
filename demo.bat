@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Демонстрация: анализатор ботнетов PCAP

echo.
echo ============================================================
echo   ШАГ 1. Офисная сеть: 14 компьютеров, 30 минут трафика.
echo   Двое заражены, но программа об этом не знает.
echo ============================================================
echo.
pause
python main.py --pcap pcaps\demo\office.pcap --out reports\demo_office.html --no-blacklist
if errorlevel 1 goto :err
start "" "reports\demo_office.html"

echo.
echo ============================================================
echo   ШАГ 2. Реальный вредоносный трафик (Stratosphere Lab):
echo   заражённое IoT-устройство.
echo ============================================================
echo.
pause
python main.py --pcap pcaps\real\test7-malicious.pcap --out reports\demo_real.html
if errorlevel 1 goto :err
start "" "reports\demo_real.html"

echo.
echo ============================================================
echo   ШАГ 3 (по желанию). Своя запись трафика.
echo   Перетащите файл .pcap / .pcapng в это окно и нажмите Enter,
echo   или просто Enter, чтобы закончить.
echo ============================================================
echo.
set "MYPCAP="
set /p MYPCAP="Файл: "
if "%MYPCAP%"=="" goto :end
python main.py --pcap %MYPCAP% --out reports\demo_live.html
if errorlevel 1 goto :err
start "" "reports\demo_live.html"
goto :end

:err
echo.
echo Что-то пошло не так. Готовые отчёты лежат в папке showcase\reports.
start "" "showcase\reports\office.html"

:end
echo.
pause
