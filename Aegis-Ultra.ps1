<#
===============================================================================
 AEGIS ULTRA – Windows Audit, Hygiene & Security Engine
 Author : Bilel Jelassi
 Version: 1.0
===============================================================================
 Purpose:
  - Continuous Windows system inspection
  - Security posture visibility
  - Storage, network & persistence auditing
  - Safe-by-default (NO destructive actions)
===============================================================================
#>

#region Admin + Core
function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}
Ensure-Admin

$Root = "$env:ProgramData\AegisUltra"
$Log  = "$Root\Aegis.log"
if (!(Test-Path $Root)) { New-Item -ItemType Directory -Path $Root | Out-Null }

function Log {
    param($Msg)
    Add-Content -Path $Log -Value "[{0}] {1}" -f (Get-Date), $Msg
}
#endregion

#region System Audit
function Audit-System {
    Log "System audit started"
    $os  = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor

    [PSCustomObject]@{
        OS        = $os.Caption
        Version   = $os.Version
        BootTime  = $os.LastBootUpTime
        CPU       = $cpu.Name
        RAM_GB    = [math]::Round($os.TotalVisibleMemorySize / 1MB,2)
    }
}
#endregion

#region Storage & Disk
function Audit-Storage {
    Log "Storage audit started"
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        [PSCustomObject]@{
            Drive   = $_.DeviceID
            SizeGB  = [math]::Round($_.Size / 1GB,2)
            FreeGB  = [math]::Round($_.FreeSpace / 1GB,2)
        }
    }
}
#endregion

#region Network
function Audit-Network {
    Log "Network audit started"
    Get-NetAdapter | Where Status -eq "Up" | Select Name, LinkSpeed, MacAddress
}
#endregion

#region Security Posture
function Audit-Security {
    Log "Security audit started"

    [PSCustomObject]@{
        DefenderStatus = (Get-Service WinDefend -ErrorAction SilentlyContinue).Status
        FirewallPublic = (Get-NetFirewallProfile | Where Name -eq Public).Enabled
        BitLockerC    = (Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus
    }
}
#endregion

#region Persistence (Cybersecurity-grade)
function Audit-Persistence {
    Log "Persistence audit started"
    Get-CimInstance Win32_StartupCommand |
    Select Name, Command, Location
}
#endregion

#region Privacy & Telemetry
function Audit-Privacy {
    Log "Privacy audit started"
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" `
        -ErrorAction SilentlyContinue
}
#endregion

#region Integrity Checks
function Audit-Integrity {
    Log "Integrity scan started"
    sfc /verifyonly | Out-Null
    Log "SFC verify-only completed"
}
#endregion

#region Automation
function Enable-AegisAutomation {
    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`""

    $trigger = New-ScheduledTaskTrigger -Daily -At 03:00
    Register-ScheduledTask -TaskName "AegisUltraAudit" `
        -Action $action -Trigger $trigger -RunLevel Highest -Force

    Log "Automation enabled"
    Write-Host "✔ Aegis Ultra scheduled daily at 03:00"
}
#endregion

#region Main Execution
Clear-Host
Write-Host "AEGIS ULTRA – Windows Audit & Security Engine" -ForegroundColor Cyan
Write-Host "Author: BiRAR Djassi`n"

Audit-System      | Format-Table
Audit-Storage     | Format-Table
Audit-Network     | Format-Table
Audit-Security    | Format-List
Audit-Persistence | Format-Table

Audit-Integrity

Write-Host "`n✔ Audit completed. Log saved to $Log" -ForegroundColor Green
Log "Full audit completed"
#endregion
