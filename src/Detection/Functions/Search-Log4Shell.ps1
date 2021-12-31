Function Search-Log4Shell {
    Param(
        $Path,
        $ZipStream,
        $ParentJar
    )
    #MD5 hash is quick and we're just using it to see if we've scanned this already
    if($null -eq $ZipStream){
        $JarHash = (Get-FileHash -Path $path -Algorithm MD5).Hash
    }
    else{
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $JarHash = [System.BitConverter]::ToString( $md5.ComputeHash($ZipStream) ).Replace("-","").ToLower()
    }
    $Result = [Log4JResult]::new()
    $Result.FileHash = $JarHash
    $Result.FilePath = $Path
    $Result.Vulnerable = $false
    $Result.ParentJarPath = $ParentJar
    $Result.CVE = @()

    # ensure we only search each jar file once
    # no infinite recursion
    if($existingResult = Test-Log4ShellAlreadyProcessed -Hash $JarHash.Hash){
        $Result.DetectedClass = $existingResult.DetectedClass
        $Result.DetectedVersion = $existingResult.DetectedVersion
        $result.Vulnerable = $existingResult.Vulnerable
        $result.CVE = $existingResult.CVE
        return $Result
    }

    $FoundVersionFromManifest = $false

    if($null -ne $ZipStream){
        $zip = [System.IO.Compression.ZipArchive]::new($ZipStream, 0)
    }
    else{
        $Zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    }
    foreach($entry in $Zip.Entries){
        if($entry.Name -match "jndilookup" -or $entry.Name -match "jndimanager" -or $entry.Name -match "socketnode" -or $entry.Name -match "manifest.mf"){
            if($entry.Name -match "jndilookup" -or $entry.Name -match "jndimanager" -or $entry.Name -match "socketnode"){
                $HashKeyCheck = 'Hash-SocketNode.class'
                if($entry.Name -match "jndilookup"){
                    $HashKeyCheck = 'Hash-JndiLookup.class'
                }
                elseif($entry.Name -match 'jndimanager'){
                    $HashKeyCheck = 'Hash-JndiManager.class'
                }
                $Stream = $entry.Open()
                $managedSHA = [System.Security.Cryptography.SHA256Managed]::Create()
                $Hash = [System.BitConverter]::ToString( $managedSHA.ComputeHash($Stream) ).Replace("-","").ToLower()
                $hashCheckResults = @(Test-Log4ShellHash -Hash $Hash -hashKey $HashKeyCheck)
                foreach($hashCheckResult in $hashCheckResults){
                    $Result.CVE += @($hashCheckResult.CVE.Split(","))
                    if(-not $FoundVersionFromManifest){
                        $Result.DetectedVersion += @($hashCheckResult.Version)
                    }
                    $Result.DetectedClass += @($entry.Name)
                    if(-not [string]::IsNullOrWhiteSpace($hashCheckResult.CVE)){
                        $Result.Vulnerable = $true
                    }
                }
                $managedSHA.Dispose()
                $Stream.Close()
            }
            elseif($entry.Name -like 'manifest.mf'){
                $Stream = $entry.Open()
                $sr = [System.IO.StreamReader]::new($Stream)
                $manifestString = $sr.ReadToEnd()
                if($ManifestResult = Test-Log4ShellManifest -MainfestString $manifestString){
                    $Result.CVE += @($ManifestResult.CVE.Split(","))
                    if(-not [string]::IsNullOrWhiteSpace($ManifestResult.Version)){
                        $FoundVersionFromManifest = $true
                        $Result.DetectedVersion = @($ManifestResult.Version)
                    }
                    if(-not ([string]::IsNullOrWhiteSpace($ManifestResult.CVE))){
                        $Result.Vulnerable = $true
                    }
                }
                $Stream.Close()
            }
        }
        elseif($entry.Name -like "*.jar"){
            $Stream = $entry.Open()
            $ParentJarParam = $Path
            if(-not [string]::IsNullOrWhiteSpace($ParentJar)){ $ParentJarParam = $ParentJar }
            $ChildResults = Search-Log4Shell -Stream $Stream -ParentJar $ParentJarParam
            foreach($cresult in $ChildResults){
                if($cresult.Vulnerable){
                    $result.EmbeddedJarVulnerable = $true
                    $result.Vulnerable = $true
                    $result.CVE += @($cResult.CVE)
                    $result.DetectedVersion += @($cresult.DetectedVersion)
                    $result.DetectedClass += @($cresult.DetectedClass)
                }
            }
            $Stream.Close()
        }
    }
    $result.DetectedClass = $result.DetectedClass | Select-Object -Unique
    $result.DetectedVersion = $result.DetectedVersion | Select-Object -Unique
    $result.CVE = $result.CVE | Select-Object -Unique
    return $result
}