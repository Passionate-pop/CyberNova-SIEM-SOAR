@echo off
REM CyberNova Minifilter Driver Build Script
REM Requires: Visual Studio + WDK (Windows Driver Kit)
REM
REM Usage:
REM   build.bat                   -> Build for x64
REM   build.bat x64               -> Build for x64
REM   build.bat arm64             -> Build for ARM64
REM
REM Prerequisites:
REM   - Visual Studio 2022 with "Desktop development with C++"
REM   - WDK for Windows 10/11

setlocal enabledelayedexpansion

set ARCH=%1
if "%ARCH%"=="" set ARCH=x64

echo Building CyberNova minifilter for %ARCH%...

REM Find the WDK build environment
if not defined BASEDIR (
    for /f "tokens=*" %%i in ('where msbuild 2^>nul') do set MSBUILD=%%i
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %ARCH%
)

REM Build the driver using the WDK MSBuild targets
msbuild cybernova.vcxproj /p:Configuration=Release /p:Platform=%ARCH% /t:Clean,Build

if %ERRORLEVEL% equ 0 (
    echo Build succeeded.
    echo Driver: %cd%\%ARCH%\Release\cybernova.sys
) else (
    echo Build failed with error %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

REM Create INF package for deployment
if not exist "deploy\%ARCH%" mkdir deploy\%ARCH%
copy %ARCH%\Release\cybernova.sys deploy\%ARCH%\
copy cybernova.inf deploy\%ARCH%\
echo Deployment package: deploy\%ARCH%\
