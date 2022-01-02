
<#PSScriptInfo

.VERSION 1.3.0

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

.DESCRIPTION 
 Detect Log4Shell 

#> 
Param(
    [ValidateSet("Host", "Registry", "Objects", "JSON")]
    $OutputType = "Objects",
    [bool]$OutputAll = $false,
    [string[]]$CVEsToDetect = @("CVE-2021-44228","CVE-2021-45046","CVE-2021-45105","CVE-2021-4104"),
    [string[]]$FilesToScan,
    [bool]$Transcript = $true
)
if($Transcript){
    $LogLocation = "$($env:TEMP)\log4j-detection-{0}.log" -f ( Get-Date -Format yyyyMMddhhmm )
    Start-Transcript -Path $LogLocation -ErrorAction SilentlyContinue    
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

class Log4JResult {
    [string]$FilePath
    [bool]$Vulnerable
    [bool]$EmbeddedJarVulnerable
    [string[]]$DetectedClass
    [string[]]$DetectedVersion
    [string[]]$CVE
    [string]$FileHash
    [string]$ParentJarPath
}

$Global:Log4ShellResults = New-Object System.Collections.Generic.List[object]

#region Functions

Get-ChildItem "$PSScriptRoot\Functions" -Filter '*.ps1' | ForEach-Object { . $_.FullName }

#endregion

$null = Get-Log4ShellIdentifiers -CVEsToDetect $CVEsToDetect


if($null -ne $FilesToScan) {
    $JavaFiles = @($FilesToScan)
}
else{
    $JavaFiles = Find-Log4ShellFiles
}

foreach($file in ($JavaFiles | Select-Object -Unique) ){
    if([string]::IsNullOrWhiteSpace($file)) { continue }
    try{
        $result = Search-Log4Shell -Path $file
        $resultAdded = $false
        if($null -eq $result){
            Write-Warning "No result returned for file $file"
        }
        elseif($result.GetType().IsArray){
            foreach($r in $result){
                if($r.GetType().Name -eq 'Log4JResult'){
                    $Global:Log4ShellResults.Add($r)
                    $resultAdded = $true
                }
            }
            if(-not $resultAdded){
                Write-Warning "Unexpected result from file $($file) - could not process"
            }
        }
        elseif($result.GetType().Name -eq 'Log4JResult'){
            $Global:Log4ShellResults.Add($result)
        }
        else{
            Write-Warning "Unexpected result from file $($file) - could not process"
        }
    }
    catch{
        if($_.Exception.Message -eq 'Exception calling "OpenRead" with "1" argument(s): "End of Central Directory record could not be found."'){
            Write-Warning "Error processing jar file $($file) - appears corrupt`n$($_.Exception.Message)"
        }
        else{
            Write-Warning "Error processing jar file $($file)`n$($_.Exception.Message)"
        }
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
    #Only write to HKLM if we're admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        $Hive = [Microsoft.Win32.RegistryHive]::LocalMachine
    }
    else{
        $Hive = [Microsoft.Win32.RegistryHive]::CurrentUser
    }
    If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, [Microsoft.Win32.RegistryView]::Registry64)

    }
    else{
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, [Microsoft.Win32.RegistryView]::Default)
    }
    $SoftwareKey = $Key.OpenSubKey('SOFTWARE', $true)
    try{
        if($Log4ShellKey = $SoftwareKey.OpenSubKey('Log4ShellDetection')){
            # removing previous results
            $null = $SoftwareKey.DeleteSubKeyTree('Log4ShellDetection')
        }
    }
    catch{
        
    }
    $null = $SoftwareKey.CreateSubKey('Log4ShellDetection')
    $Log4ShellDetectionKey = $SoftwareKey.OpenSubKey('Log4ShellDetection', $true)
    foreach($vFile in $OutputSet){
        $null = $Log4ShellDetectionKey.CreateSubKey($vFile.FileHash)
        $tempSubKey = $Log4ShellDetectionKey.OpenSubKey($vFile.FileHash, $true)
        $Log4ShellDetectionKey.SetValue("FilePath", "")
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "FilePath" -Value $vFile.FilePath
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "Vulnerable" -Value $vFile.Vulnerable
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "EmbeddedJarVulnerable" -Value $vFile.EmbeddedJarVulnerable
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "DetectedClass" -Value ($vFile.DetectedClass -join ",")
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "DetectedVersion" -Value ($vFile.DetectedVersion -join ",")
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "CVE" -Value ($vFile.CVE -join ",")
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "FileHash" -Value $vFile.FileHash
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "ParentJarPath" -Value $vFile.ParentJarPath
    }
}
elseif($OutputType -eq "Objects"){
    $OutputSet
}
elseif($OutputType -eq 'JSON'){
    $OutputSet | ConvertTo-JSON
}
if($Transcript){
    Stop-Transcript
}