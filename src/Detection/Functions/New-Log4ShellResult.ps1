Function New-Log4ShellResult{
    Param()
    return New-Object -TypeName PSObject -Property @{
        'FilePath' = ''
        'Vulnerable' = $false
        'EmbeddedJarVulnerable' = $false
        'DetectedClass' = @()
        'DetectedVersion' = @()
        'CVE' = @()
        'FileHash' = ''
        'ParentJarPath' = ''
    }
}