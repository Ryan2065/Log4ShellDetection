
<#PSScriptInfo

.VERSION 1.4.2

.GUID f95ba891-b109-4180-89e0-c2827eababef

.AUTHOR Ryan Ephgrave

.COMPANYNAME EphingAdmin

.COPYRIGHT MIT

.TAGS 

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<#
.SYNOPSIS
Log4Shell Detection script 

.DESCRIPTION
Uses known hash values of .CLASS files in Log4J to find jar files with Log4J code that has a Log4Shell vulnerability

.PARAMETER OutputType
Type of output. Objects will return as PSObject, Host will return a summary with the objects, Registry will output to HLKM:\Software\Log4ShellDetection, and JSON will return a JSON string

.PARAMETER OutputAll
If true - will return all jar files scanned. If false, returns only results that are flagged as having a vulnerability

.PARAMETER CVEsToDetect
Array of CVEs to detect. If the first array item is a comma separate list, it'll split that and use it. This allows for sending a comma separate list from the command line instead of a PowerShell array object.

.PARAMETER FilesToScan
Skip scanning the drive and instead scan specific files. Wants an array, but if sent a comma separate list it'll convert it to an array.

.PARAMETER Transcript
If true, will output a transcript to $env:Temp. If false, no transcript generated

.PARAMETER FoldersToScan
Scan specific folders on the system

.EXAMPLE
PS> . .\Log4ShellDetection.ps1 "Registry" 0 "CVE-2021-44228,CVE-2021-45046" "" 0
Example usable from cmd.exe to scan for two specific CVEs, disable transcripts, and put results in the registry.

.EXAMPLE
PS> . .\Log4ShellDetection.ps1
Run the script with default settings

.EXAMPLE
PS> . .\Log4ShellDetection.ps1 -FilesToScan @('c:\jarfile.jar') -Transcript $false
Scans a specific file with transcript off

.NOTES
.Author: Ryan Ephgrave
#>

Param(
    [ValidateSet("Host", "Registry", "Objects", "JSON", "CountVulnerable", "Silent")]
    $OutputType = "Objects",
    [bool]$TatooRegistry = $false,
    [bool]$OutputAll = $false,
    [string[]]$CVEsToDetect = @("CVE-2021-44228","CVE-2021-45046","CVE-2021-45105","CVE-2021-4104","CVE-2021-44832"),
    [string[]]$FilesToScan,
    [string[]]$FoldersToScan,
    [bool]$Transcript = $true,
    [bool]$LowProcessPriority = $false,
    [bool]$SkipNetworkDrives = $false
)

if($Transcript){
    $LogLocation = "$($env:TEMP)\log4j-detection-{0}.log" -f ( Get-Date -Format yyyyMMddhhmm )
    $null = Start-Transcript -Path $LogLocation -ErrorAction SilentlyContinue    
}

if($LowProcessPriority){
    $currentProc = [System.Diagnostics.Process]::GetCurrentProcess()
    $CurrentProcesPriority = $currentProc.PriorityClass
    $currentProc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$Global:Log4ShellResults = New-Object System.Collections.Generic.List[object]

#region Functions

Get-ChildItem "$PSScriptRoot\Functions" -Filter '*.ps1' | ForEach-Object { . $_.FullName }

#endregion

$FixedCVEToDetect = @()

foreach($instance in $CVEsToDetect){
    $FixedCVEToDetect += @($instance.Split(","))
}

$null = Get-Log4ShellIdentifiers -CVEsToDetect $FixedCVEToDetect

$FilesToScanFixed = @()

foreach($file in $FilesToScan){
    if(-not [string]::IsNullOrWhiteSpace($file)){
        $FilesToScanFixed += @($file.Split(','))
    }
}

$FoldersToScanFixed = @()

foreach($folder in $FoldersToScan){
    if(-not [string]::IsNullOrWhiteSpace($folder)){
        $FoldersToScanFixed += @($folder.Split(','))
    }
}

$LogScanFolders = @()

if($FilesToScanFixed.Count -gt 0) {
    $null = $FilesToScan | Start-Log4ShellScan
}
elseif($FoldersToScanFixed.Count -gt 0){
    $JavaFiles = @()
    foreach($Folder in $FoldersToScanFixed){
        $null = Find-Log4ShellFiles -root $folder | Start-Log4ShellScan
    }
}
else{
    if($SkipNetworkDrives){
        $Roots = @((Get-CimInstance -ClassName 'Win32_LogicalDisk' -Filter 'DriveType = 3').DeviceId)
    }
    else{
        $PSDrives = Get-PSDrive -PSProvider FileSystem
        $Roots = @($PSDrives.Root)
    }
    foreach($r in $roots){
        $null = Find-Log4ShellFiles -root "$($r.TrimEnd('\'))\" | Start-Log4ShellScan
    }
}

$VulnerableFiles = @(foreach($r in $Log4ShellResults){ if($r.Vulnerable){ $r } })

$OutputSet = $VulnerableFiles
if($OutputAll){
    $OutputSet = $Log4ShellResults
}

if($OutputType -eq 'Host'){
    Write-Host "--- Summary ----"
    Write-Host "Scanned $($Log4ShellResults.Count) jar files and embedded jar files"
    Write-Host "Found $($VulnerableFiles.Count) vulnerabilities"
    foreach($vFile in $OutputSet){
        if($vFile.Vulnerable){
            Write-host "  Vulnerabile file: $($vFile.FilePath) - CVEs: $($vFile.CVE -join ",") - Detected Version: $($vFile.DetectedVersion -join ",") - Detected Problem Class Files: $($vFile.DetectedClass -join ",")"
        }
        else{
            Write-Host "  Not Vulnerable file: $($vFile.FilePath)"
        }
    }
}
elseif($OutputType -eq "Registry"){
    Write-Log4ShellRegistry -OutputSet $OutputSet
}
elseif($OutputType -eq "Objects"){
    $OutputSet
}
elseif($OutputType -eq 'JSON'){
    $OutputSet | ConvertTo-JSON
}
elseif($OutputType -eq 'CountVulnerable'){
    $VulnerableFiles.count
}

if($TatooRegistry -and ( $OutputType -ne 'Registry' )){
    Write-Log4ShellRegistry -OutputSet $OutputSet
}

if($LowProcessPriority -and ($null -ne $CurrentProcesPriority)){
    $currentProc = [System.Diagnostics.Process]::GetCurrentProcess()
    $currentProc.PriorityClass = $CurrentProcesPriority
}

if($Transcript){
    $null = Stop-Transcript
}