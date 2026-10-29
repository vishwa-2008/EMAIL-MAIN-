@echo off
setlocal
cd /d "%~dp0"

set "JAVA_BIN=C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot\bin\java.exe"
if not exist "%JAVA_BIN%" (
    set "JAVA_BIN=javaw.exe"
)

if not exist "%~dp0target\java-email-authentication-1.0.0.jar" (
    echo Building project for first run...
    if exist "%~dp0.tools\apache-maven-3.9.6\bin\mvn.cmd" (
        set "JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot"
        call "%~dp0.tools\apache-maven-3.9.6\bin\mvn.cmd" package
    ) else (
        echo Maven was not found. Build the project with Maven, then run this launcher again.
        exit /b 1
    )
)

if not exist "%~dp0target\java-email-authentication-1.0.0.jar" (
    echo Build failed: application JAR was not created.
    exit /b 1
)

echo Starting website at http://localhost:8080
start "" "%JAVA_BIN%" -jar "%~dp0target\java-email-authentication-1.0.0.jar"
