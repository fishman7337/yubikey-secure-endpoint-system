$ErrorActionPreference = "Stop"

$taskName = "YubiWatchTask"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcher = Join-Path $root "watchdog_launcher.vbs"

if (-not (Test-Path -LiteralPath $launcher)) {
    throw "Missing launcher: $launcher"
}

function Install-StartupShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LauncherPath,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $startupFolder = [Environment]::GetFolderPath("Startup")
    if ([string]::IsNullOrWhiteSpace($startupFolder)) {
        throw "Could not resolve the current user's Startup folder."
    }

    $shortcutPath = Join-Path $startupFolder "YubiWatch.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $env:WINDIR "System32\wscript.exe"
    $shortcut.Arguments = "`"$LauncherPath`""
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.WindowStyle = 7
    $shortcut.Description = "Start YubiWatch at logon."
    $shortcut.Save()

    Write-Host "Installed startup shortcut '$shortcutPath'."
}

function Remove-StartupShortcut {
    $startupFolder = [Environment]::GetFolderPath("Startup")
    if ([string]::IsNullOrWhiteSpace($startupFolder)) {
        return
    }

    $shortcutPath = Join-Path $startupFolder "YubiWatch.lnk"
    if (Test-Path -LiteralPath $shortcutPath) {
        Remove-Item -LiteralPath $shortcutPath -Force
        Write-Host "Removed fallback startup shortcut '$shortcutPath'."
    }
}

$action = New-ScheduledTaskAction `
    -Execute "wscript.exe" `
    -Argument "`"$launcher`"" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Description "Starts YubiWatch at logon, locks when the configured YubiKey is absent, and can open the local dashboard." `
        -Force | Out-Null

    Remove-StartupShortcut
    Write-Host "Installed scheduled task '$taskName'."
}
catch {
    Write-Warning "Could not register scheduled task '$taskName': $($_.Exception.Message)"
    Write-Warning "Falling back to the current user's Startup folder."
    Install-StartupShortcut -LauncherPath $launcher -WorkingDirectory $root
}
