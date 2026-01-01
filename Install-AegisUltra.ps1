<#
 AEGIS ULTRA – Installer & Automation
 Author: Bilel Jelassi
#>

$Target = "$env:ProgramFiles\AegisUltra"
if (!(Test-Path $Target)) {
    New-Item -ItemType Directory -Path $Target | Out-Null
}

Copy-Item ".\Aegis-Ultra.ps1" "$Target\Aegis-Ultra.ps1" -Force

Write-Host "✔ Aegis Ultra installed to $Target"

powershell -ExecutionPolicy Bypass -File "$Target\Aegis-Ultra.ps1"
