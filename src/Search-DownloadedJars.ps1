<#
    I wrote this file to get all versions of Log4J from Maven, see if they are vulnerable to any of the CVEs in the CVE array,
    and if they are download the .jar file and get identifying information (hashes, version, etc)

    Results are put in a hash, converted to JSON, and then sent to the clipboard.

    They can be pasted in Get-Log4ShellIdentifiers.ps1
#>

$Log4ShellCVE = @(
    'CVE-2021-44228',
    'CVE-2021-45046',
    'CVE-2021-45105',
    'CVE-2021-4104'
)

Function ProcessLog4JFile {
    Param(
        $Path
    )
    try{
        $Zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    }
    catch{
        Write-host "$Path"
        $Global:ErrorJars += @($Path)
        return
    }
    
    $Log4JEntry = @{

    }
    foreach($entry in $Zip.Entries){
        if($entry.Name -match "jndilookup.class" -or $entry.Name -match "jndimanager.class" -or $entry.Name -match "socketnode.class" -or $entry.Name -match "manifest.mf"){
            if($entry.Name -eq "jndilookup.class" -or $entry.Name -eq "jndimanager.class" -or $entry.Name -eq "socketnode.class"){
                $Stream = $entry.Open()
                $managedSHA = [System.Security.Cryptography.SHA256Managed]::Create()
                $Hash = [System.BitConverter]::ToString( $managedSHA.ComputeHash($Stream) ).Replace("-","").ToLower()
                $managedSHA.Dispose()
                $Stream.Close()
                $Log4JEntry["Hash-$($entry.Name)"] = $Hash
            }
            elseif($entry.Name -like 'manifest.mf'){
                $Stream = $entry.Open()
                $sr = [System.IO.StreamReader]::new($Stream)
                $manifestString = $sr.ReadToEnd()
                $FoundReleaseVersion = $false
                $IsLog4J = $false
                foreach($line in $manifestString.Split("`n").Trim()){
                    if($line -like '*Log4jReleaseVersion*'){
                        $FoundReleaseVersion = $true
                        $Log4JEntry['ReleaseVersionString'] = $line.Trim()
                        $Log4JEntry['Version'] = ($line.Split(":")[-1]).Trim()
                    }
                    if($line -like '*Implementation-Title: log4j*'){
                        $IsLog4J = $true
                    }
                }
                if(-not $FoundReleaseVersion -and $IsLog4J){
                    foreach($line in $manifestString.Split("`n").Trim()){
                        if($line -like '*Implementation-Version*'){
                            $Log4JEntry['ImplementationVersionString'] = $line.Trim()
                            $Log4JEntry['Version'] = ($line.Split(":")[-1]).Trim()
                        }
                    }
                }
                $Stream.Close()
            }
        }
    }
    if($Log4JEntry["ReleaseVersionString"]){ $Log4JEntry }
    elseif($Log4JEntry["ImplementationVersionString"]){ $Log4JEntry }
}

$Global:ErrorJars = @()
$results = @()

Function GetCVEs {
    Param($pageURL)
    $Global:MainPageHtml = Invoke-WebRequest -Uri $pageURL
    $Vulnerabilities = ($MainPageHtml.ParsedHtml.body.getElementsByTagName('a') | Where-Object { $_.GetAttributeNode('class').Value -eq 'vuln' }).outerText
    foreach($v in $Vulnerabilities){
        if($Log4ShellCVE -contains $v){
            $v
        }
    }
}

$Log4JCoreVersions = Invoke-RestMethod -Uri 'https://search.maven.org/solrsearch/select?q=g:org.apache.logging.log4j%20AND%20a:log4j&core=gav&start=0&rows=90'
$Log4JVersions = Invoke-RestMethod -Uri 'https://search.maven.org/solrsearch/select?q=g:log4j%20AND%20a:log4j&core=gav&start=0&rows=14'

foreach($version in $Log4JCoreVersions.Response.docs){
    $MainPage = "https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/$($version.v)"
    $DownloadJar = "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/$($version.v)/log4j-core-$($version.v).jar"
    $CVEs = @(GetCVEs -pageURL $MainPage)
    if($CVEs.Count -gt 0){
        $JarFile = "$env:TEMP\log4j-core-$($version.v).jar"
        if(-not (Test-Path $JarFile)){
            $null = Invoke-WebRequest $DownloadJar -OutFile $JarFile
        }
        $result = ProcessLog4JFile $JarFile
        $Result['CVE'] = $CVEs -join ","
        $Result['MavenVersion'] = $version.v
        $Results += $result
        #$null = Remove-Item $JarFile -Force
    }
}

foreach($version in $Log4JVersions.Response.docs){
    $MainPage = "https://mvnrepository.com/artifact/log4j/log4j/$($version.v)"
    $DownloadJar = "https://repo1.maven.org/maven2/log4j/log4j/$($version.v)/log4j-$($version.v).jar"
    $CVEs = @(GetCVEs -pageURL $MainPage)
    if($CVEs.Count -gt 0){
        $JarFile = "$env:TEMP\log4j-$($version.v).jar"
        if(-not (Test-Path $JarFile)){
            $null = Invoke-WebRequest $DownloadJar -OutFile $JarFile
        }
        $result = ProcessLog4JFile $JarFile
        if($null -eq $result){
            Write-Warning "Error on $MainPage"
            $global:ErrorV = $version
            return
        }
        $Result['CVE'] = $CVEs -join ","
        $Result['MavenVersion'] = $version.v
        $Results += $result
        #$null = Remove-Item $JarFile -Force
    }
}

$Results | ConvertTo-JSON | clip.exe

