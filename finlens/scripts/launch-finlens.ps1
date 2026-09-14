# FinLens portable launcher. ASCII-only so Windows PowerShell 5.1 can parse it.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$LogFile = Join-Path $Root "finlens-launcher.log"

function Write-LaunchLog($message) {
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $message
    Add-Content -Path $LogFile -Value $line -Encoding ASCII
}

try {
    Set-Content -Path $LogFile -Value ("FinLens launcher " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -Encoding ASCII
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
    [System.Windows.Forms.Application]::EnableVisualStyles()
} catch {
    Add-Content -Path $LogFile -Value $_.Exception.Message
    throw
}

$Backend = Join-Path $Root "backend"
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"
$Requirements = Join-Path $Backend "requirements.txt"
$EnvFile = Join-Path $Backend ".env"
$EnvExample = Join-Path $Backend ".env.example"
$script:ServerProcess = $null
$script:AppUrl = "http://127.0.0.1:8000"

function Get-ThemeColor([string]$hex) {
    $h = $hex.TrimStart("#")
    return [System.Drawing.Color]::FromArgb(
        [Convert]::ToInt32($h.Substring(0, 2), 16),
        [Convert]::ToInt32($h.Substring(2, 2), 16),
        [Convert]::ToInt32($h.Substring(4, 2), 16)
    )
}

function Hide-ConsoleWindow {
    try {
        $code = @"
using System;
using System.Runtime.InteropServices;
public static class FinLensNative {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
        Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
        $hwnd = [FinLensNative]::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) { [FinLensNative]::ShowWindow($hwnd, 0) | Out-Null }
    } catch { }
}

$bg     = Get-ThemeColor "0A0A0F"
$panel  = Get-ThemeColor "12121A"
$card   = Get-ThemeColor "16161F"
$green  = Get-ThemeColor "00FF88"
$text   = Get-ThemeColor "F0F0F5"
$muted  = Get-ThemeColor "8888A0"
$red    = Get-ThemeColor "FF3366"
$border = Get-ThemeColor "2A2A36"
$uiFont = New-Object System.Drawing.Font("Segoe UI", 10)
$uiBold = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$form = New-Object System.Windows.Forms.Form
$form.Text = "FinLens"
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ClientSize = New-Object System.Drawing.Size(520, 640)
$form.BackColor = $bg
$form.ForeColor = $text
$form.Font = $uiFont

$header = New-Object System.Windows.Forms.Panel
$header.Location = New-Object System.Drawing.Point(0, 0)
$header.Size = New-Object System.Drawing.Size(520, 118)
$header.BackColor = $panel
$form.Controls.Add($header)

$logo = New-Object System.Windows.Forms.Label
$logo.Text = "F"
$logo.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$logo.ForeColor = $bg
$logo.BackColor = $green
$logo.TextAlign = "MiddleCenter"
$logo.Location = New-Object System.Drawing.Point(28, 28)
$logo.Size = New-Object System.Drawing.Size(44, 44)
$header.Controls.Add($logo)

$title = New-Object System.Windows.Forms.Label
$title.Text = "FinLens"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = $text
$title.BackColor = $panel
$title.Location = New-Object System.Drawing.Point(84, 24)
$title.AutoSize = $true
$header.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = "AI Financial Safety Net  |  Live Gemini"
$subtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subtitle.ForeColor = $muted
$subtitle.BackColor = $panel
$subtitle.Location = New-Object System.Drawing.Point(86, 62)
$subtitle.AutoSize = $true
$header.Controls.Add($subtitle)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Starting..."
$status.Font = $uiBold
$status.ForeColor = $green
$status.BackColor = $bg
$status.Location = New-Object System.Drawing.Point(28, 138)
$status.Size = New-Object System.Drawing.Size(464, 28)
$form.Controls.Add($status)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(28, 172)
$progress.Size = New-Object System.Drawing.Size(464, 8)
$progress.Style = "Continuous"
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 8
$form.Controls.Add($progress)

$log = New-Object System.Windows.Forms.TextBox
$log.Multiline = $true
$log.ReadOnly = $true
$log.ScrollBars = "Vertical"
$log.BorderStyle = "FixedSingle"
$log.BackColor = $card
$log.ForeColor = $muted
$log.Font = New-Object System.Drawing.Font("Consolas", 9)
$log.Location = New-Object System.Drawing.Point(28, 198)
$log.Size = New-Object System.Drawing.Size(464, 340)
$log.WordWrap = $true
$form.Controls.Add($log)

$openBtn = New-Object System.Windows.Forms.Button
$openBtn.Text = "Open FinLens"
$openBtn.Enabled = $false
$openBtn.FlatStyle = "Flat"
$openBtn.FlatAppearance.BorderSize = 0
$openBtn.BackColor = $green
$openBtn.ForeColor = $bg
$openBtn.Font = $uiBold
$openBtn.Location = New-Object System.Drawing.Point(28, 556)
$openBtn.Size = New-Object System.Drawing.Size(224, 48)
$form.Controls.Add($openBtn)

$stopBtn = New-Object System.Windows.Forms.Button
$stopBtn.Text = "Stop"
$stopBtn.FlatStyle = "Flat"
$stopBtn.FlatAppearance.BorderColor = $border
$stopBtn.BackColor = $panel
$stopBtn.ForeColor = $text
$stopBtn.Font = $uiBold
$stopBtn.Location = New-Object System.Drawing.Point(268, 556)
$stopBtn.Size = New-Object System.Drawing.Size(224, 48)
$form.Controls.Add($stopBtn)

function Write-UiLog([string]$message) {
    Write-LaunchLog $message
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $message
    $updater = {
        $log.AppendText($line + [Environment]::NewLine)
        $log.SelectionStart = $log.Text.Length
        $log.ScrollToCaret()
    }.GetNewClosure()
    if ($form.InvokeRequired) { [void]$form.Invoke($updater) } else { & $updater }
}

function Set-UiStatus([string]$textValue, [int]$pct, $color) {
    $updater = {
        $status.Text = $textValue
        if ($color) { $status.ForeColor = $color }
        if ($pct -ge 0 -and $pct -le 100) { $progress.Value = $pct }
    }.GetNewClosure()
    if ($form.InvokeRequired) { [void]$form.Invoke($updater) } else { & $updater }
}

function Find-Python {
    $commands = @("py", "python", "python3")
    foreach ($cmdName in $commands) {
        $found = Get-Command $cmdName -ErrorAction SilentlyContinue
        if (-not $found) { continue }
        try {
            if ($cmdName -eq "py") {
                $out = & $cmdName -3 -c "import sys; print(sys.executable)" 2>$null
            } else {
                $out = & $cmdName -c "import sys; print(sys.executable)" 2>$null
            }
            if ($out) { return ($out | Select-Object -Last 1).ToString().Trim() }
        } catch { }
    }
    return $null
}

function Get-FreePort {
    $listener = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

function Read-EnvKey([string]$path, [string]$name) {
    if (-not (Test-Path $path)) { return "" }
    foreach ($line in Get-Content -Path $path -ErrorAction SilentlyContinue) {
        if ($line -match ("^\s*" + [regex]::Escape($name) + "\s*=\s*(.*)$")) {
            return $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
    return ""
}

function Ensure-EnvFile {
    if (-not (Test-Path $EnvFile)) {
        if (Test-Path $EnvExample) { Copy-Item $EnvExample $EnvFile }
        else {
            @(
                "GOOGLE_API_KEY=",
                "FINLENS_MODEL=gemini-3.6-flash",
                "PORT=8000"
            ) | Set-Content -Path $EnvFile -Encoding ASCII
        }
    }
    $key = Read-EnvKey $EnvFile "GOOGLE_API_KEY"
    $placeholder = ($key -eq "") -or ($key -like "your-*") -or ($key.Length -lt 12)
    if ($placeholder) {
        $ask = {
            [Microsoft.VisualBasic.Interaction]::InputBox(
                "Paste your Google Gemini API key to run FinLens on this computer.",
                "FinLens Gemini API key",
                ""
            )
        }
        $prompt = if ($form.InvokeRequired) { $form.Invoke($ask) } else { & $ask }
        if (-not $prompt) { throw "A Gemini API key is required. Get one at https://aistudio.google.com/apikey" }
        $escaped = $prompt.Trim()
        $content = @(Get-Content $EnvFile)
        $written = $false
        $newLines = foreach ($line in $content) {
            if ($line -match "^\s*GOOGLE_API_KEY\s*=") {
                $written = $true
                "GOOGLE_API_KEY=$escaped"
            } else { $line }
        }
        if (-not $written) { $newLines += "GOOGLE_API_KEY=$escaped" }
        $newLines | Set-Content -Path $EnvFile -Encoding ASCII
    }
}

function Stop-Server {
    if ($script:ServerProcess -ne $null -and -not $script:ServerProcess.HasExited) {
        try { Stop-Process -Id $script:ServerProcess.Id -Force -ErrorAction SilentlyContinue } catch { }
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $($script:ServerProcess.Id)" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
}

function Start-Bootstrap {
    try {
        Set-UiStatus "Checking Python..." 10 $green
        Write-UiLog "Project folder: $Root"

        if (-not (Test-Path $Backend)) { throw "backend folder not found. Keep FinLens.bat inside the FinLens folder." }

        $python = Find-Python
        if (-not $python) {
            Start-Process "https://www.python.org/downloads/windows/"
            throw "Python 3.11+ was not found. Install Python, tick Add python.exe to PATH, then run FinLens.bat again."
        }
        Write-UiLog "Python: $python"

        Set-UiStatus "Preparing virtual environment..." 22 $green
        if (-not (Test-Path $VenvPython)) {
            Write-UiLog "Creating .venv (first run on this PC)..."
            & $python -m venv (Join-Path $Backend ".venv")
            if ($LASTEXITCODE -ne 0) { throw "Could not create a virtual environment." }
        }

        Set-UiStatus "Installing packages..." 40 $green
        Write-UiLog "Installing requirements (needs internet on first run)..."
        & $VenvPython -m pip install -q -r $Requirements
        if ($LASTEXITCODE -ne 0) {
            Write-UiLog "Quiet install failed, retrying with logs..."
            & $VenvPython -m pip install -r $Requirements
            if ($LASTEXITCODE -ne 0) { throw "Package install failed. Check your internet connection." }
        }
        Write-UiLog "Dependencies ready."

        Set-UiStatus "Checking Gemini key..." 62 $green
        Ensure-EnvFile
        Write-UiLog "Environment file ready."

        $port = Get-FreePort
        $script:AppUrl = "http://127.0.0.1:$port"
        Set-UiStatus "Starting live server..." 78 $green
        Write-UiLog "Launching Gemini-backed API on $($script:AppUrl)"

        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $VenvPython
        $info.Arguments = "main.py"
        $info.WorkingDirectory = $Backend
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.EnvironmentVariables["PORT"] = "$port"
        $info.EnvironmentVariables["FINLENS_RELOAD"] = "false"
        $script:ServerProcess = New-Object System.Diagnostics.Process
        $script:ServerProcess.StartInfo = $info
        [void]$script:ServerProcess.Start()

        $ready = $false
        for ($i = 0; $i -lt 80; $i++) {
            if ($script:ServerProcess.HasExited) {
                $err = $script:ServerProcess.StandardError.ReadToEnd()
                throw "Server exited early. $err"
            }
            try {
                $resp = Invoke-WebRequest -Uri ($script:AppUrl + "/api/health") -UseBasicParsing -TimeoutSec 2
                if ($resp.StatusCode -eq 200) { $ready = $true; break }
            } catch {
                Start-Sleep -Milliseconds 400
            }
        }
        if (-not $ready) { throw "Server did not become ready. Close other FinLens windows and try again." }

        Set-UiStatus ("Live  |  " + $script:AppUrl) 100 $green
        Write-UiLog "Ready. Opening browser..."
        $enabler = { $openBtn.Enabled = $true }.GetNewClosure()
        if ($form.InvokeRequired) { [void]$form.Invoke($enabler) } else { & $enabler }
        Start-Process $script:AppUrl
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-LaunchLog $errMsg
        Set-UiStatus "Could not start" 100 $red
        Write-UiLog $errMsg
        $show = {
            [System.Windows.Forms.MessageBox]::Show(
                $errMsg,
                "FinLens",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }.GetNewClosure()
        if ($form.InvokeRequired) { [void]$form.Invoke($show) } else { & $show }
    }
}

$openBtn.Add_Click({ if ($script:AppUrl) { Start-Process $script:AppUrl } })
$stopBtn.Add_Click({ $form.Close() })
$form.Add_FormClosing({ Stop-Server })
$form.Add_Shown({
    Hide-ConsoleWindow
    $thread = New-Object System.Threading.Thread ([System.Threading.ThreadStart]{ Start-Bootstrap })
    $thread.IsBackground = $true
    $thread.Start()
})

[void]$form.ShowDialog()
Stop-Server
exit 0
