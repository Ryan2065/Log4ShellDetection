Function Test-Log4ShellManifest{
    <#
    .SYNOPSIS
    Checks a Java manafest file for the Log4J versions associated with Log4Shell CVEs
    
    .DESCRIPTION
    Checks a Java manafest file for the Log4J versions associated with Log4Shell CVEs
    
    .PARAMETER MainfestString
    Manifest file contents

    #>
    Param($MainfestString)

    $IsOlderLog4J = $false
    $SplitLines = $MainfestString.Split("`n")
    $Ids = Get-Log4ShellIdentifiers
    foreach($line in $SplitLines){
        if([string]::IsNullOrWhiteSpace($line)){ continue }
        if($line -like '*Log4jReleaseVersion*'){
            foreach($id in $ids){
                if($id.ReleaseVersionString -eq $line.Trim()){
                    return $id
                }
            }
        }
        if($line -like '*Implementation-Title: log4j*'){
            $IsOlderLog4J = $true
        }
    }

    if($IsOlderLog4J){
        foreach($line in $SplitLines){
            if([string]::IsNullOrWhiteSpace($line)){ continue }
            if($line -like '*Implementation-Version*'){
                foreach($id in $ids){
                    if($id.ImplementationVersionString -eq $line.Trim()){
                        return $id
                    }
                }
            }
        }
    }
}