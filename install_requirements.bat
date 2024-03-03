@echo off

>nul 2>&1 where "pip.exe" || (
    echo Impossible to install requirements because "pip.exe" was not found in your system.
    echo Please check the "Add Python 3.x to PATH" checkbox on the Python setup installer, and try again.
    echo:
    echo Press {ANY KEY} to continue ...
    >nul pause
    exit /b 0
)

if exist "requirements.txt" (
    pip install -r "requirements.txt" && (
        exit /b 0
    )
)

for %%A in (
    colorama
    geoip2
    prettytable
    psutil
    pyshark
    requests
    urllib3
) do (
    pip install %%A
)

exit /b 0
