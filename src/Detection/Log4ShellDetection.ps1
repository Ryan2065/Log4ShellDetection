Param(
    [ValidateSet("Host", "Registry")]
    $OutputType = "Host"
)

$LogLocation = "$($env:TEMP)\log4j-detection-{0}.log" -f ( Get-Date -Format yyyyMMddhhmm )
Start-Transcript -Path $LogLocation -ErrorAction SilentlyContinue

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

$JavaFiles = Find-Log4ShellFiles

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

if($OutputType -eq 'Host'){
    Write-Host "--- Summary ----"
    Write-Host "Scanned $($Log4ShellResults.Count) jar files and embedded jar files"
    Write-Host "Found $($VulnerableFiles.Count) vulnerabilities"
    foreach($vFile in $VulnerableFiles){
        Write-host "  Vulnerabile file: $($vFile.FilePath) - CVEs: $($vFile.CVE -join ",") - Detected Version: $($vFile.DetectedVersion -join ",") - Detected Problem Class Files: $($vFile.DetectedClass -join ",")"
    }
}
elseif($OutputType -eq "Registry"){
    #Only write to HKLM if we're admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
        $RegHiveLocation = "HKLM:\SOFTWARE\Log4ShellDetection"
    }
    else{
        $RegHiveLocation = "HKCU:\SOFTWARE\Log4ShellDetection"
    }
    $null = Remove-Item -Path $RegHiveLocation -Force -Recurse -ErrorAction SilentlyContinue
    $null = New-Item -Path $RegHiveLocation -Type Directory -Force -ErrorAction SilentlyContinue
    foreach($vFile in $VulnerableFiles){
        $null = New-Item -Path "$RegHiveLocation\$($vFile.FileHash)" -Type Directory -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "FilePath" -Value $vFile.FilePath -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "Vulnerable" -Value $vFile.Vulnerable -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "EmbeddedJarVulnerable" -Value $vFile.EmbeddedJarVulnerable -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "DetectedClass" -Value ($vFile.DetectedClass -join ",") -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "DetectedVersion" -Value ($vFile.DetectedVersion -join ",") -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "CVE" -Value ($vFile.CVE -join ",") -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "FileHash" -Value $vFile.FileHash -Force
        Set-ItemProperty -Path "$RegHiveLocation\$($vFile.FileHash)" -Name "ParentJarPath" -Value $vFile.ParentJarPath -Force
    }
}
Stop-Transcript