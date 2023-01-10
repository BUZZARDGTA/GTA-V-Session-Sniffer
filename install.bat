@echo off

if exist "requirements.txt" (
    pip install -r requirements.txt
) else (
    >nul 2>&1 where "pip.exe" || (
        echo Impossible to install requirements because "pip.exe" was not found in your system.
        echo Please check the "Add Python 3.x to PATH" checkbox on the Python setup installer, and try again.
        echo:
        echo Press {ANY KEY} to continue ...
        >nul pause
        exit 0
    )
    for %%A in (
        pyshark
        urllib3
        requests
        colorama
    ) do (
        pip install %%A
    )
)

exit /b 0
