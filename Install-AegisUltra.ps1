<#
 AEGIS ULTRA – Master Installer
 Author: Bilel Jelassi
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

$Target = "$env:ProgramFiles\AegisUltra"
if (!(Test-Path $Target)) { New-Item -ItemType Directory -Path $Target -Force | Out-Null }

if (Test-Path ".\Aegis-Ultra.ps1") {
    Copy-Item ".\Aegis-Ultra.ps1" "$Target\Aegis-Ultra.ps1" -Force
    Write-Host "[✔] Installation Successful. Aegis Ultra is now in Program Files." -ForegroundColor Green
    & "$Target\Aegis-Ultra.ps1"
} else {
    Write-Host "[!] Error: Aegis-Ultra.ps1 not found in current folder." -ForegroundColor Red
}