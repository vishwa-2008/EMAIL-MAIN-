$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$JavaBin = "C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot\bin\java.exe"
if (-not (Test-Path $JavaBin)) {
    $JavaBin = "javaw.exe"
}

$JarPath = "$ScriptDir\target\java-email-authentication-1.0.0.jar"
if (-not (Test-Path $JarPath)) {
    Write-Host "Building project package..." -ForegroundColor Cyan
    $env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot"
    & "$ScriptDir\.tools\apache-maven-3.9.6\bin\mvn.cmd" package
    if ($LASTEXITCODE -ne 0) {
        throw "Maven package failed with exit code $LASTEXITCODE."
    }
}

$Port = if ($env:PORT) { $env:PORT } else { "8080" }
Start-Process -FilePath $JavaBin -ArgumentList "-jar", "`"$JarPath`"" -WorkingDirectory $ScriptDir
Write-Host "Website starting at http://localhost:$Port" -ForegroundColor Green
