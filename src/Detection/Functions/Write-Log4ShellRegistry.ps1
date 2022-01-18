Function Write-Log4ShellRegistry{
    Param($OutputSet)
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
        Set-Log4ShellRegistryValue -Key $tempSubKey -Name "LastScanned" -Value ([DateTime]::UtcNow.ToString('yyyyMMddhhmmss'))
    }
}