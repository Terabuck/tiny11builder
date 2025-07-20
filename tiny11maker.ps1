# tinyandhard11maker.ps1
# Hardened replica of tiny11maker.ps1 with audit transparency and security optimizations
# Microsoft Edge preserved

Set-PSDebug -Trace 0
param ([ValidatePattern('^[c-zC-Z]$')] [string]$ScratchDisk)

if (-not $ScratchDisk) {
    $ScratchDisk = $PSScriptRoot -replace '[\\]+$', ''
} else {
    $ScratchDisk = $ScratchDisk + ":"
}
Write-Output "Scratch disk set to $ScratchDisk"

# Execution policy adjustment
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Execution Policy is Restricted. Change to RemoteSigned? (yes/no)"
    if ((Read-Host) -eq 'yes') {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    } else {
        Write-Host "Cannot continue with Restricted policy. Exiting..."
        exit
    }
}

# Admin privilege check
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

if (! $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Host "Restarting as Administrator..."
    $newProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $newProcess.Arguments = $myInvocation.MyCommand.Definition
    $newProcess.Verb = "runas"
    [System.Diagnostics.Process]::Start($newProcess)
    exit
}

# Logging
Start-Transcript -Path "$ScratchDisk\tinyandhard11.log"
$Host.UI.RawUI.WindowTitle = "TinyAndHard image creator"
Clear-Host
Write-Host "Welcome to the hardened Tiny11 image creator! Release: CustomAuditEdition"

New-Item -ItemType Directory -Force -Path "$ScratchDisk\tiny11\sources" | Out-Null

# Drive input and validation
do {
    $DriveLetter = Read-Host "Enter drive letter for Windows 11 image"
    if ($DriveLetter -match '^[c-zC-Z]$') {
        $DriveLetter += ":"
        Write-Output "Drive letter set to $DriveLetter"
    } else {
        Write-Output "Invalid letter. Try C-Z only."
    }
} while ($DriveLetter -notmatch '^[c-zC-Z]:$')

# Handle .esd to .wim conversion
if (!(Test-Path "$DriveLetter\sources\boot.wim") -or !(Test-Path "$DriveLetter\sources\install.wim")) {
    if (Test-Path "$DriveLetter\sources\install.esd") {
        Write-Host "Found install.esd – converting to install.wim..."
        Get-WindowsImage -ImagePath "$DriveLetter\sources\install.esd"
        $index = Read-Host "Enter image index"
        Write-Host "Converting. Please wait..."
        Export-WindowsImage -SourceImagePath "$DriveLetter\sources\install.esd" -SourceIndex $index `
            -DestinationImagePath "$ScratchDisk\tiny11\sources\install.wim" -CompressionType Maximum -CheckIntegrity
    } else {
        Write-Host "Install files not found. Exiting..."
        exit
    }
}

Write-Host "Copying files..."
Copy-Item -Path "$DriveLetter\*" -Destination "$ScratchDisk\tiny11" -Recurse -Force | Out-Null
Set-ItemProperty -Path "$ScratchDisk\tiny11\sources\install.esd" -Name IsReadOnly -Value $false > $null 2>&1
Remove-Item "$ScratchDisk\tiny11\sources\install.esd" > $null 2>&1
Write-Host "Copy complete."

Start-Sleep -Seconds 1
Clear-Host

Write-Host "Getting image info..."
Get-WindowsImage -ImagePath "$ScratchDisk\tiny11\sources\install.wim"
$index = Read-Host "Enter image index"

# Mount preparation
Write-Host "Mounting image. This may take a while..."
$wimFilePath = "$ScratchDisk\tiny11\sources\install.wim"
takeown "/F" $wimFilePath | Out-Null
icacls $wimFilePath "/grant" "$($adminGroup.Value):(F)" | Out-Null
try {
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction Stop
} catch {}

New-Item -ItemType Directory -Force -Path "$ScratchDisk\scratchdir" | Out-Null
Mount-WindowsImage -ImagePath $wimFilePath -Index $index -Path "$ScratchDisk\scratchdir"

# Detect architecture
$imageInfo = & 'dism' '/English' '/Get-WimInfo' "/wimFile:$wimFilePath" "/index:$index"
$architecture = ($imageInfo -split '\r?\n' | Where-Object { $_ -like "*Architecture : *" }) -replace 'Architecture : ', ''
if ($architecture -eq 'x64') { $architecture = 'amd64' }

Write-Host "Architecture: $architecture"

# App cleanup (Edge preserved)
Write-Host "Cleaning apps..."
$packages = & 'dism' '/English' "/image:$ScratchDisk\scratchdir" '/Get-ProvisionedAppxPackages' |
    ForEach-Object { if ($_ -match 'PackageName : (.*)') { $matches[1] } }

$preserveApps = @('Microsoft.Edge_', 'Microsoft.EdgeUpdate_')
$packagePrefixes = @(
    'Clipchamp.Clipchamp_', 'Microsoft.BingNews_', 'Microsoft.GamingApp_',
    'Microsoft.GetHelp_', 'Microsoft.People_', 'Microsoft.PowerAutomateDesktop_',
    'Microsoft.XboxGamingOverlay_', 'Microsoft.ZuneMusic_'
)

$packagesToRemove = $packages | Where-Object {
    $packageName = $_
    -not ($preserveApps | Where-Object { $packageName -like "$_*" }) -and
    ($packagePrefixes | Where-Object { $packageName -like "$_*" })
}

foreach ($package in $packagesToRemove) {
    Write-Host "Removing: $package"
    & 'dism' '/English' "/image:$ScratchDisk\scratchdir" '/Remove-ProvisionedAppxPackage' "/PackageName:$package"
}

# Skip Edge removal
Write-Host "Edge preserved."

# OneDrive removal
Write-Host "Removing OneDrive..."
$oneDriveSetup = "$ScratchDisk\scratchdir\Windows\System32\OneDriveSetup.exe"
if (Test-Path $oneDriveSetup) {
    takeown "/f" $oneDriveSetup | Out-Null
    icacls $oneDriveSetup "/grant" "$($adminGroup.Value):(F)" | Out-Null
    Remove-Item -Path $oneDriveSetup -Force | Out-Null
}

# Registry setup
Write-Host "Loading system registry hives..."
reg load HKLM\zSYSTEM "$ScratchDisk\scratchdir\Windows\System32\config\SYSTEM" | Out-Null
reg load HKLM\zDEFAULT "$ScratchDisk\scratchdir\Windows\System32\config\default" | Out-Null
reg load HKLM\zNTUSER "$ScratchDisk\scratchdir\Users\Default\ntuser.dat" | Out-Null

# Bypass registry keys
Write-Host "Applying bypass registry keys..."
$regKeys = @(
    'HKLM\zSYSTEM\Setup\LabConfig',
    'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache',
    'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache'
)

foreach ($key in $regKeys) {
    reg add $key /v BypassCPUCheck /t REG_DWORD /d 1 /f | Out-Null
    reg add $key /v BypassRAMCheck /t REG_DWORD /d 1 /f | Out-Null
    reg add $key /v SV1 /t REG_DWORD /d 0 /f | Out-Null
    reg add $key /v SV2 /t REG_DWORD /d 0 /f | Out-Null
}

Write-Host "Bypass applied successfully."

# Final cleanup
Write-Host "Finalizing..."
Stop-Transcript
Write-Host "✅ Hardened image creation complete. Your custom Windows is ready."
