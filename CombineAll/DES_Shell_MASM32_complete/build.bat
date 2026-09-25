@echo off
setlocal

if "%IRVINE%"=="" set "IRVINE=C:\Irvine"
set "ASM_EXE=ml.exe"
set "LINKER=link.exe"
set "KERNEL_LIB=kernel32.lib"
set "USER_LIB=user32.lib"

where ml.exe >nul 2>nul
if errorlevel 1 (
  if exist "C:\masm32\bin\ml.exe" (
    set "ASM_EXE=C:\masm32\bin\ml.exe"
    set "LINKER=C:\masm32\bin\link.exe"
    set "KERNEL_LIB=C:\masm32\lib\kernel32.lib"
    set "USER_LIB=C:\masm32\lib\user32.lib"
  ) else (
    echo ERROR: ml.exe was not found. Use an x86 Native Tools Command Prompt or install MASM32.
    exit /b 1
  )
)

"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" module_a.asm
if errorlevel 1 exit /b 1
"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" des_key_schedule.asm
if errorlevel 1 exit /b 1
"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" module_C.asm
if errorlevel 1 exit /b 1
"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" displayHexDump.asm
if errorlevel 1 exit /b 1
"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" Histrogram.asm
if errorlevel 1 exit /b 1
"%ASM_EXE%" /nologo /c /coff /I "%IRVINE%" des_selftest.asm
if errorlevel 1 exit /b 1

"%LINKER%" /nologo /subsystem:console /machine:x86 /out:des_shell.exe module_a.obj des_key_schedule.obj module_C.obj displayHexDump.obj Histrogram.obj "%IRVINE%\Irvine32.lib" "%KERNEL_LIB%" "%USER_LIB%"
if errorlevel 1 exit /b 1

"%LINKER%" /nologo /subsystem:console /machine:x86 /out:des_selftest.exe des_selftest.obj des_key_schedule.obj module_C.obj "%IRVINE%\Irvine32.lib" "%KERNEL_LIB%" "%USER_LIB%"
if errorlevel 1 exit /b 1

echo Build completed.
des_selftest.exe
exit /b %errorlevel%
