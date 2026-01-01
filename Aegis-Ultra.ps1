<#
===============================================================================
 AEGIS ULTRA – SOVEREIGN FORENSIC EDITION (ULTIMATE)
 Advanced Threat Hunting, NVMe Health & System Hardening
 Author : Bilel Jelassi | Version: 3.0
===============================================================================
#>

# --- PRE-FLIGHT & ENCODING ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

# Admin Auto-Elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Fix for Get-PhysicalDisk & Module Prep
Import-Module Storage -ErrorAction SilentlyContinue

# --- CONFIGURATION ---
$VT_KEY = [Environment]::GetEnvironmentVariable("VT_API_KEY", "User")
$LogDir = "$env:USERPROFILE\Documents\SystemLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir "Aegis_Master_Report_$(Get-Date -Format 'yyyyMMdd').log"
$Quarantine = "C:\Quarantine"
if (-not (Test-Path $Quarantine)) { New-Item $Quarantine -ItemType Directory -Force | Out-Null }

function Write-Aegis($Message, $Status = "INFO") {
    $Color = switch ($Status) { "OK" {"Green"} "WARN" {"Yellow"} "FAIL" {"Red"} "SEC" {"Magenta"} default {"Cyan"} }
    $TS = Get-Date -Format "HH:mm:ss"
    Write-Host "[$TS] " -NoNewline -ForegroundColor Gray
    Write-Host "$($Message.PadRight(55, '.'))" -NoNewline -ForegroundColor White
    Write-Host " [$Status]" -ForegroundColor $Color
    "[$TS] $Status : $Message" | Out-File -FilePath $LogFile -Append
}

function Show-Header {
    Clear-Host
    $C = "Cyan"; $B = "Blue"; $G = "Gray"; $M = "Magenta"
    Write-Host "  ▄▄▄       ▓█████   ▄████  ██▓  ██████     █    ██  ██▓  ▄▄▄█████▓ ██▀███   ▄▄▄      " -ForegroundColor $C
    Write-Host " ▒████▄     ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    " -ForegroundColor $C
    Write-Host " ▒██  ▀█▄   ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄       ▓██  ▒██░▒██▒  ▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  " -ForegroundColor $C
    Write-Host " ░██▄▄▄▄██  ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒    ▓▓█  ░██░░██░  ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ " -ForegroundColor $B
    Write-Host "  ▓█   ▓██▒ ░▒████▒░▒▓███▀▒░██░▒██████▒▒    ▒▒█████▓ ░██░    ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒" -ForegroundColor $B
    Write-Host "  ▒▒   ▓▒█░ ░░ ▒░ ░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░    ░▒▓▒ ▒ ▒ ░▓      ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░" -ForegroundColor $G
    Write-Host "                                v3.0 MASTER EDITION | BY BILEL JELASSI`n" -ForegroundColor $M
}

# --- EXECUTION ENGINE ---
Show-Header

# PHASE 1: SYSTEM32 DLL INTEGRITY & VIRUSTOTAL
Write-Aegis "Auditing System32 DLL Signatures" "SEC"
$Unsigned = Get-ChildItem -Path "C:\Windows\System32\*.dll" | Get-AuthenticodeSignature | Where-Object { $_.Status -ne "Valid" }
if ($Unsigned) {
    Write-Aegis "DETECTED: $($Unsigned.Count) Unsigned/Modified DLLs!" "FAIL"
    foreach ($Dll in $Unsigned) {
        if ($VT_KEY) {
            try {
                $Hash = (Get-FileHash $Dll.Path -Algorithm SHA256).Hash
                $Uri = "https://www.virustotal.com/api/v3/files/$Hash"
                $Resp = Invoke-RestMethod -Uri $Uri -Headers @{"x-apikey"="$VT_KEY"} -Method Get -ErrorAction Stop
                $Malicious = $Resp.data.attributes.last_analysis_stats.malicious
                if ($Malicious -gt 0) {
                    Write-Aegis "THREAT CONFIRMED: $($Dll.FileName) [$Malicious Flags]" "FAIL"
                    Move-Item -Path $Dll.Path -Destination $Quarantine -Force
                }
            } catch { Write-Aegis "Unknown/New DLL: $($Dll.FileName)" "WARN" }
        }
    }
} else { Write-Aegis "Core DLL Integrity Verified" "OK" }

# PHASE 2: PROCESS PATH INTEGRITY (Anti-Spoofing)
Write-Aegis "Auditing System Process Path Integrity" "SEC"
Get-Process | Where-Object { $_.Name -match "svchost|lsass|wininit|services" } | ForEach-Object {
    if ($_.Path -and $_.Path -notlike "*C:\Windows\System32*") {
        Write-Aegis "SPOOFED PROCESS: $($_.Name) running from $($_.Path)" "FAIL"
    }
}

# PHASE 3: SHADOW ADMIN & PRIVILEGE AUDIT
Write-Aegis "Scanning for Shadow Administrators" "SEC"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    if ($_.Name -notlike "*Administrator*" -and $_.Name -notlike "*Domain Admins*") {
        Write-Aegis "SHADOW ADMIN DETECTED: $($_.Name)" "FAIL"
    }
}

# PHASE 4: NETWORK PERIMETER (Port Intelligence)
Write-Aegis "Auditing Active Network Listeners" "SEC"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($_.LocalPort -gt 1024) {
        $SystemProcs = "lsass", "svchost", "wininit", "services", "System", "AvastSvc"
        if ($SystemProcs -contains $Proc.Name) {
            Write-Aegis "System Listener: Port $($_.LocalPort) ($($Proc.Name))" "OK"
        } else {
            Write-Aegis "UNKNOWN LISTENER: Port $($_.LocalPort) ($($Proc.Name))" "WARN"
        }
    }
}

# PHASE 5: ADVANCED PERSISTENCE (Registry & WMI)
Write-Aegis "Hunting WMI Event Persistence" "SEC"
$WMI = Get-WmiObject -Namespace root\subscription -Class __EventConsumer
if ($WMI) {
    foreach ($C in $WMI) { Write-Aegis "WMI Persistence: $($C.Name)" "WARN" }
}

Write-Aegis "Stalking Registry Run Keys" "SEC"
$Paths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($P in $Paths) {
    if (Test-Path $P) {
        Get-ItemProperty $P | Get-Member -MemberType NoteProperty | ForEach-Object {
            if ($_.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider") {
                Write-Aegis "Auto-Start Found: $($_.Name)" "WARN"
            }
        }
    }
}

# PHASE 6: NVMe HEALTH
Write-Aegis "NVMe S.M.A.R.T. Health Analysis" "INFO"
Get-PhysicalDisk | ForEach-Object { 
    $H = $_.HealthStatus
    Write-Aegis "Drive $($_.DeviceID) Status: $H" (if($H -eq 'Healthy'){"OK"}else{"FAIL"})
}

# PHASE 7: PURGE & REPAIR
Write-Aegis "Executing Privacy Sweep & Junk Purge" "INFO"
$Junk = @("$env:TEMP\*", "C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Windows\SoftwareDistribution\Download\*")
foreach ($P in $Junk) { Remove-Item $P -Recurse -Force -ErrorAction SilentlyContinue }

Write-Aegis "Internet Boost & DNS Refresh" "INFO"
ipconfig /flushdns | Out-Null
netsh winsock reset | Out-Null

Write-Aegis "Vulnerability Fix (System File Repair)" "INFO"
sfc /scannow | Out-Null

Write-Host "`n[✔] MASTER AUDIT COMPLETE. DATA SECURED: $LogDir" -ForegroundColor Green
Invoke-Item $LogDir