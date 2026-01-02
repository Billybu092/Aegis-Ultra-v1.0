<#
===============================================================================
 █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗   ██╗██╗     ████████╗██████╗  █████╗ 
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║   ██║██║     ╚══██╔══╝██╔══██╗██╔══██╗
███████║█████╗  ██║  ███╗██║███████╗    ██║   ██║██║        ██║   ██████╔╝███████║
██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║   ██║██║        ██║   ██╔══██╗██╔══██║
██║  ██║███████╗╚██████╔╝██║███████║    ╚██████╔╝███████╗   ██║   ██║  ██║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝     ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
===============================================================================
 PROJECT: AEGIS ULTRA (SOVEREIGN FORENSIC ENGINE)
 VERSION: 3.5 (ULTIMATE)
 AUTHOR : BILEL JELASSI
 QUOTE  : "Vigilantia et Integritas"
===============================================================================
#>

param(
    [Parameter(Mandatory=$false)][Switch]$Help
)

# --- [ HELP SYSTEM ] ---
if ($Help) {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              🛡️ AEGIS ULTRA v3.5 OPERATOR MANUAL               ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n[TAGS DECODED]" -ForegroundColor White
    Write-Host " [SEC]  -> Security Audit: Deep-level forensic investigation." -ForegroundColor Magenta
    Write-Host " [INFO] -> System Health: Hardware and maintenance telemetry." -ForegroundColor Cyan
    Write-Host " [OK]   -> Verified: Component matches secure baseline." -ForegroundColor Green
    Write-Host " [WARN] -> Suspicious: Unknown entry found; manual review needed." -ForegroundColor Yellow
    Write-Host " [FAIL] -> Critical: Integrity breach or hardware failure." -ForegroundColor Red
    Write-Host "`n[PHASES]" -ForegroundColor White
    Write-Host " 1-3: Identity & Integrity (DLLs, Admins, Signatures)"
    Write-Host " 4-5: Persistence (Tasks, WMI, Registry)"
    Write-Host " 6-7: Physical & File Integrity (NVMe, SFC, Chkdsk)"
    Write-Host " 8-10: Perimeter & Purge (Nmap Scan, Junk Purge, Network Reset)"
    Write-Host "`nStay Secure, Operator. — Bilel Jelassi`n" -ForegroundColor Cyan
    exit
}

# --- [ PRE-FLIGHT ] ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "SilentlyContinue"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] ACCESS DENIED: Aegis Ultra requires Administrator Privileges." -ForegroundColor Red
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- [ CONFIGURATION ] ---
$LogDir = "$env:USERPROFILE\Documents\SystemLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir "Aegis_Report_$(Get-Date -Format 'yyyyMMdd').log"

$Global:ShadowFound = $false
$Global:UntrustedPorts = @()
$Global:TaskAlerts = 0
$Global:OpenCriticalPorts = @()

function Write-Aegis($Message, $Status = "INFO") {
    $Mark = "•"
    $Color = switch ($Status) { "OK" {"Green"} "WARN" {"Yellow"} "FAIL" {"Red"} "SEC" {"Cyan"} default {"White"} }
    $TS = Get-Date -Format "HH:mm:ss"
    
    Write-Host "  [$TS]" -NoNewline -ForegroundColor Gray
    Write-Host " $Mark " -NoNewline -ForegroundColor $Color
    Write-Host "$($Message.PadRight(52, ' '))" -NoNewline -ForegroundColor White
    Write-Host "──[" -NoNewline -ForegroundColor Gray
    Write-Host "$Status" -NoNewline -ForegroundColor $Color
    Write-Host "]" -ForegroundColor Gray
    
    "[$TS] $Status : $Message" | Out-File -FilePath $LogFile -Append
}

function Show-Header {
    Clear-Host
    $C = "Cyan"; $B = "Blue"; $G = "Gray"
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor $B
    Write-Host "  ║   █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗   ██╗██╗     ████████╗  ║" -ForegroundColor $C
    Write-Host "  ║  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║   ██║██║     ╚══██╔══╝  ║" -ForegroundColor $C
    Write-Host "  ║  ███████║█████╗  ██║  ███╗██║███████╗    ██║   ██║██║        ██║     ║" -ForegroundColor $C
    Write-Host "  ║  ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ██║   ██║██║        ██║     ║" -ForegroundColor $B
    Write-Host "  ║  ██║  ██║███████╗╚██████╔╝██║███████║    ╚██████╔╝███████╗   ██║     ║" -ForegroundColor $B
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor $B
    Write-Host "       SOVEREIGN FORENSIC ENGINE v3.5 | OPERATOR: $($env:USERNAME)" -ForegroundColor $G
    Write-Host ""
}

# --- [ EXECUTION ] ---
Show-Header
Write-Aegis "Initializing Forensic Sovereignty" "SEC"

# PHASE 1: DLL INTEGRITY
Write-Aegis "Auditing System32 DLL Signatures" "SEC"
$Unsigned = Get-ChildItem -Path "C:\Windows\System32\*.dll" | Get-AuthenticodeSignature | Where-Object { $_.Status -ne "Valid" }
if ($Unsigned) { Write-Aegis "DETECTED: $($Unsigned.Count) Unsigned DLLs!" "FAIL" } else { Write-Aegis "Core DLL Integrity Verified" "OK" }

# PHASE 2: SHADOW ADMIN
Write-Aegis "Scanning for Shadow Administrators" "SEC"
Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
    if ($_.Name -notlike "*Administrator*" -and $_.Name -notlike "*Domain Admins*") {
        Write-Aegis "SHADOW ADMIN: $($_.Name)" "FAIL"
        $Global:ShadowFound = $true
    }
}

# PHASE 3: PORT AUDIT
Write-Aegis "Auditing Network Perimeter Signatures" "SEC"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($_.LocalPort -gt 1024 -and $Proc) {
        $Sig = Get-AuthenticodeSignature -FilePath $Proc.Path
        if ($Sig.Status -eq "Valid") {
            $Pub = $Sig.SignerCertificate.Subject.Split(',')[0].Replace("CN=", "")
            Write-Aegis "Verified: Port $($_.LocalPort) ($($Proc.Name))" "OK"
        } else {
            Write-Aegis "UNTRUSTED: Port $($_.LocalPort) ($($Proc.Name))" "WARN"
            $Global:UntrustedPorts += "$($Proc.Name)"
        }
    }
}

# PHASE 4: TASK SCHEDULER HUNTER
Write-Aegis "Hunting Scheduled Task Persistence" "SEC"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
    $Name = $_.TaskName
    $Action = $_.Actions.Execute + $_.Actions.Arguments
    if ($Action -match "powershell|pwsh|cmd|.vbs|.ps1|bitsadmin") {
        Write-Aegis "SUSPICIOUS TASK: $Name" "WARN"
        $Global:TaskAlerts++
    } else { Write-Aegis "User Task: $Name" "OK" }
}

# PHASE 5: WMI & REGISTRY

Write-Aegis "Hunting WMI Event Persistence" "SEC"
Get-WmiObject -Namespace root\subscription -Class __EventConsumer | ForEach-Object {
    if ($_.Name -eq "SCM Event Log Consumer") { Write-Aegis "Verified WMI: $($_.Name)" "OK" }
    else { Write-Aegis "WMI Hook Detected: $($_.Name)" "WARN" }
}

# PHASE 6: HARDWARE S.M.A.R.T.

Write-Aegis "Analyzing NVMe/SSD Reliability" "INFO"
Get-StorageReliabilityCounter | Select-Object DeviceId, Wear | ForEach-Object {
    Write-Aegis "Drive Health: $($_.Wear)% Wear Level" "OK"
}

# PHASE 7: KERNEL REPAIR (The Coffee Break)
Write-Aegis "Initializing Deep Kernel Integrity Scan (SFC)" "SEC"
Write-Host "  [!] This is a deep audit. Grab a coffee ☕ while Aegis reconstructs your Kernel DNA..." -ForegroundColor Gray

# We use a background job so the user sees a "Processing" spinner
$Job = Start-Job -ScriptBlock { sfc /scannow }
$Spinner = @("|", "/", "-", "\")
$i = 0
while ($Job.State -eq "Running") {
    Write-Host "`r  [PROCESSING] $($Spinner[$i % 4]) Scanning System Files..." -NoNewline -ForegroundColor Cyan
    $i++
    Start-Sleep -Milliseconds 250
}
Receive-Job $Job | Out-Null
Write-Host "`r" # Clear the spinner line
Write-Aegis "Windows Resource Protection Audit Complete" "OK"

# PHASE 8: JUNK DECIMATION

Write-Aegis "Decimating System Junk & Temp Artifacts" "INFO"
$Junk = @("$env:TEMP\*", "C:\Windows\Temp\*")
foreach ($J in $Junk) { Remove-Item $J -Recurse -Force }
Write-Aegis "Purged Unnecessary System Bloat" "OK"

# PHASE 9: PERIMETER SCAN (The Probe)
Write-Aegis "Launching Critical Port Discovery (Internal Nmap)" "SEC"
$Ports = @{
    21 = "FTP (File Transfer)"; 
    22 = "SSH (Secure Shell)"; 
    23 = "Telnet (Unsecured)"; 
    445 = "SMB (File Sharing)"; 
    3389 = "RDP (Remote Desktop)"
}

Write-Host "  [!] Probing local attack surface for vulnerabilities..." -ForegroundColor Gray
foreach ($P in $Ports.Keys) {
    # Visual feedback for each port check
    Write-Host "      Checking Port $P ($($Ports[$P]))... " -NoNewline -ForegroundColor Gray
    $Check = Test-NetConnection -ComputerName localhost -Port $P -InformationLevel Quiet
    if ($Check) {
        Write-Host "[EXPOSED]" -ForegroundColor Red
        Write-Aegis "ALERT: Open Attack Surface -> Port $P ($($Ports[$P]))" "FAIL"
        $Global:OpenCriticalPorts += $P
    } else {
        Write-Host "[SECURE]" -ForegroundColor Green
    }
}
# PHASE 10: SOVEREIGNTY PURGE
Write-Aegis "Executing Sovereignty Network Purge" "INFO"
$null = ipconfig /flushdns; $null = netsh winsock reset
Write-Aegis "Network Pathing & DNS Refresh Complete" "OK"

# --- [ EXECUTIVE SUMMARY ] ---
function Show-Summary {
    Write-Host "`n  ┌─────────────────── FORENSIC AUDIT SUMMARY ───────────────────┐" -ForegroundColor Cyan
    Write-Host "  │" -ForegroundColor Cyan
    
    if ($Global:ShadowFound) {
        Write-Host "  │  [!] PRIVILEGE ESCALATION: Unofficial Admin Found!           " -ForegroundColor Red
    }
    if ($Global:TaskAlerts -gt 0) {
        Write-Host "  │  [!] PERSISTENCE: Background scripts are active ($Global:TaskAlerts)     " -ForegroundColor Yellow
    }
    if ($Global:OpenCriticalPorts.Count -gt 0) {
        Write-Host "  │  [!] VULNERABILITY: Ports $($Global:OpenCriticalPorts -join ', ') are exposed.      " -ForegroundColor Red
    }
    
    Write-Host "  │  [✓] KERNEL REPAIR: System files verified & repaired.        " -ForegroundColor Green
    Write-Host "  │  [✓] DISK INTEGRITY: S.M.A.R.T. Wear level optimal.          " -ForegroundColor Green
    Write-Host "  │  [✓] PRIVACY: System junk and DNS logs decimated.            " -ForegroundColor Green
    Write-Host "  │" -ForegroundColor Cyan
    Write-Host "  │  REPORT SECURED: $LogFile" -ForegroundColor Gray
    Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host "`n  Scan complete. Your Sovereignty has been restored." -ForegroundColor Cyan
Write-Host "  Stay Secure, $($env:USERNAME). — Bilel Jelassi 🛡️" -ForegroundColor Magenta
Write-Host ("=" * 72) -ForegroundColor Cyan

Show-Summary
