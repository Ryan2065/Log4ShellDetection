
<#PSScriptInfo

.VERSION 1.0

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
    [ValidateSet("Host", "Registry", "Objects")]
    $OutputType = "Objects"
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

Function Find-Log4ShellFiles {
    Param(
        $root
    )
    $results = @()
    if([string]::IsNullOrWhiteSpace($root)){
        $PSDrives = Get-PSDrive -PSProvider FileSystem
        $Roots = @($PSDrives.Root)
        foreach($root in $roots){
            $results += (& cmd /c robocopy /l "$($root)" null *.jar *.war *.ear /ns /njh /njs /np /nc /ndl /xjd /mt /s).trim()
        }
    }
    else{
        $results += (& cmd /c robocopy /l "$($root)" null *.jar *.war *.ear /ns /njh /njs /np /nc /ndl /xjd /mt /s).trim()
    }
    
    foreach($result in $results){
        if([string]::IsNullOrWhiteSpace($result)){ continue }
        if($result.ToLower().EndsWith('.jar') -or $result.ToLower().EndsWith('.war') -or $result.ToLower().EndsWith('.ear')){
            $result
        }
    }
}


Function Get-Log4ShellIdentifiers{
    Param()
    if($null -eq $Script:Log4ShellIds){
    #output from Search-DownloadedJars.ps1
        $Script:Log4ShellIds = @'
    [
    {
        "Hash-JndiLookup.class":  "7f0add9055958365137a8cc7a90969a43c44b20280323bdac718c1ff3795beb8",
        "MavenVersion":  "2.3.2",
        "Version":  "2.3.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.3.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "89535e03625d7ed5074d12eab85a9b27a643fcaf9ed62b152371d209ee90ce80"
    },
    {
        "Hash-JndiLookup.class":  "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
        "MavenVersion":  "2.12.4",
        "Version":  "2.12.4",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.12.4",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "a954ff8c69d43a40dac017ec01ecc56f6c39d9122cb3c388abbe89b975a6fe95"
    },
    {
        "Hash-JndiLookup.class":  "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
        "MavenVersion":  "2.17.1",
        "Version":  "2.17.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.17.1",
        "CVE":  "CVE-2021-4104",
        "Hash-JndiManager.class":  "3588a6aaf84fa79215a1cc5d12dee69413b8772656c73bdf26ef35df713b1091"
    },
    {
        "Hash-JndiLookup.class":  "0ad99a95ff637fc966fc4ce5fe1f9e78d3b24b113282f9990b95a6fde3383d9c",
        "MavenVersion":  "2.3.1",
        "Version":  "2.3.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.3.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "6ce4436eca5edc852d375cbc831cd652b80fc16f6238cd2b22bd115b3735460e"
    },
    {
        "Hash-JndiLookup.class":  "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
        "MavenVersion":  "2.12.3",
        "Version":  "2.12.3",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.12.3",
        "CVE":  "CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "f04dd01860bb32750a47fc3f6b29a41b4dd04736fadf0fd63c4f1909d845afd2"
    },
    {
        "Hash-JndiLookup.class":  "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
        "MavenVersion":  "2.17.0",
        "Version":  "2.17.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.17.0",
        "CVE":  "CVE-2021-4104",
        "Hash-JndiManager.class":  "9c2a6ea36c79fa23da59cc0f6c52c07ce54ca145ddd654790a3116d2b24de51b"
    },
    {
        "Hash-JndiLookup.class":  "febbc7867784d0f06934fec59df55ee45f6b24c55b17fff71cc4fca80bf22ebb",
        "MavenVersion":  "2.12.2",
        "Version":  "2.12.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.12.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "b1960d63a3946f9e16e1920624f37c152b58b98932ed04df99ed5d9486732afb"
    },
    {
        "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
        "MavenVersion":  "2.16.0",
        "Version":  "2.16.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.16.0",
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "Hash-JndiManager.class":  "5210e6aae7dd8a61cd16c56937c5f2ed43941487830f46e99d0d3f45bfa6f953"
    },
    {
        "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
        "MavenVersion":  "2.15.0",
        "Version":  "2.15.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.15.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-4104",
        "Hash-JndiManager.class":  "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e"
    },
    {
        "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
        "MavenVersion":  "2.14.1",
        "Version":  "2.14.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.14.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6"
    },
    {
        "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
        "MavenVersion":  "2.14.0",
        "Version":  "2.14.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.14.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6"
    },
    {
        "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
        "MavenVersion":  "2.13.3",
        "Version":  "2.13.3",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.13.3",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
    },
    {
        "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
        "MavenVersion":  "2.13.2",
        "Version":  "2.13.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.13.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
    },
    {
        "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
        "MavenVersion":  "2.13.1",
        "Version":  "2.13.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.13.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
    },
    {
        "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
        "MavenVersion":  "2.13.0",
        "Version":  "2.13.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.13.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
    },
    {
        "Hash-JndiLookup.class":  "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
        "MavenVersion":  "2.12.1",
        "Version":  "2.12.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.12.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de"
    },
    {
        "Hash-JndiLookup.class":  "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
        "MavenVersion":  "2.12.0",
        "Version":  "2.12.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.12.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.11.2",
        "Version":  "2.11.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.11.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.11.1",
        "Version":  "2.11.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.11.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.11.0",
        "Version":  "2.11.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.11.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.10.0",
        "Version":  "2.10.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.10.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.9.1",
        "Version":  "2.9.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.9.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
        "MavenVersion":  "2.9.0",
        "Version":  "2.9.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.9.0",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
    },
    {
        "Hash-JndiLookup.class":  "d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15",
        "MavenVersion":  "2.8.2",
        "Version":  "2.8.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.8.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407"
    },
    {
        "Hash-JndiLookup.class":  "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
        "MavenVersion":  "2.8.1",
        "Version":  "2.8.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.8.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
    },
    {
        "Hash-JndiLookup.class":  "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
        "MavenVersion":  "2.8",
        "Version":  "2.8",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.8",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
    },
    {
        "Hash-JndiLookup.class":  "cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae",
        "MavenVersion":  "2.7",
        "Version":  "2.7",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.7",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
    },
    {
        "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
        "MavenVersion":  "2.6.2",
        "Version":  "2.6.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.6.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
    },
    {
        "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
        "MavenVersion":  "2.6.1",
        "Version":  "2.6.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.6.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
    },
    {
        "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
        "MavenVersion":  "2.6",
        "Version":  "2.6",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.6",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
    },
    {
        "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
        "MavenVersion":  "2.5",
        "Version":  "2.5",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.5",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
    },
    {
        "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
        "MavenVersion":  "2.4.1",
        "Version":  "2.4.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.4.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
    },
    {
        "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
        "MavenVersion":  "2.4",
        "Version":  "2.4",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.4",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
    },
    {
        "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
        "MavenVersion":  "2.3",
        "Version":  "2.3",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.3",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
    },
    {
        "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
        "MavenVersion":  "2.2",
        "Version":  "2.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.2",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
    },
    {
        "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
        "MavenVersion":  "2.1",
        "Version":  "2.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.1",
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c",
        "MavenVersion":  "2.0.2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0.2",
        "Version":  "2.0.2"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e",
        "MavenVersion":  "2.0.1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0.1",
        "Version":  "2.0.1"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29",
        "MavenVersion":  "2.0",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0",
        "Version":  "2.0"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2",
        "MavenVersion":  "2.0-rc2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-rc2",
        "Version":  "2.0-rc2"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
        "MavenVersion":  "2.0-rc1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-rc1",
        "Version":  "2.0-rc1"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
        "Hash-JndiLookup.class":  "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
        "MavenVersion":  "2.0-beta9",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta9",
        "Version":  "2.0-beta9"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta8",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta8",
        "Version":  "2.0-beta8"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta7",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta7",
        "Version":  "2.0-beta7"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta6",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta6",
        "Version":  "2.0-beta6"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta5",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta5",
        "Version":  "2.0-beta5"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta4",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta4",
        "Version":  "2.0-beta4"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta3",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta3",
        "Version":  "2.0-beta3"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta2",
        "Version":  "2.0-beta2"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-beta1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-beta1",
        "Version":  "2.0-beta1"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-alpha2",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-alpha2",
        "Version":  "2.0-alpha2"
    },
    {
        "CVE":  "CVE-2021-45105,CVE-2021-4104",
        "MavenVersion":  "2.0-alpha1",
        "ReleaseVersionString":  "Log4jReleaseVersion: 2.0-alpha1",
        "Version":  "2.0-alpha1"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74",
        "MavenVersion":  "1.2.17",
        "Version":  "1.2.17",
        "ImplementationVersionString":  "Implementation-Version: 1.2.17"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46",
        "MavenVersion":  "1.2.16",
        "Version":  "1.2.16",
        "ImplementationVersionString":  "Implementation-Version: 1.2.16"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4",
        "MavenVersion":  "1.2.15",
        "Version":  "1.2.15",
        "ImplementationVersionString":  "Implementation-Version: 1.2.15"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7",
        "MavenVersion":  "1.2.14",
        "Version":  "1.2.14",
        "ImplementationVersionString":  "Implementation-Version: 1.2.14"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7",
        "MavenVersion":  "1.2.13",
        "Version":  "1.2.13",
        "ImplementationVersionString":  "Implementation-Version: 1.2.13"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
        "MavenVersion":  "1.2.9",
        "Version":  "1.2.9",
        "ImplementationVersionString":  "Implementation-Version: 1.2.9"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c",
        "MavenVersion":  "1.2.12",
        "Version":  "1.2.12",
        "ImplementationVersionString":  "Implementation-Version: 1.2.12"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6",
        "MavenVersion":  "1.2.11",
        "Version":  "1.2.11",
        "ImplementationVersionString":  "Implementation-Version: 1.2.11"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9",
        "MavenVersion":  "1.2.8",
        "Version":  "1.2.8",
        "ImplementationVersionString":  "Implementation-Version: 1.2.8"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
        "MavenVersion":  "1.2.7",
        "Version":  "1.2.7",
        "ImplementationVersionString":  "Implementation-Version: 1.2.7"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
        "MavenVersion":  "1.2.6",
        "Version":  "1.2.6",
        "ImplementationVersionString":  "Implementation-Version: 1.2.6"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a",
        "MavenVersion":  "1.2.5",
        "Version":  "1.2.5",
        "ImplementationVersionString":  "Implementation-Version: 1.2.5"
    },
    {
        "CVE":  "CVE-2021-4104",
        "Hash-SocketNode.class":  "6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d",
        "MavenVersion":  "1.2.4",
        "Version":  "1.2.4",
        "ImplementationVersionString":  "Implementation-Version: 1.2.4"
    }
]

'@ | ConvertFrom-JSON
    }
    return $Script:Log4ShellIds
}
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
Function Test-Log4ShellAlreadyProcessed {
    Param($Hash)

    foreach($existingResult in $Global:Log4ShellResults){
        if($existingResult.FileHash -eq $Hash){
            return $existingResult
        }
    }
}
Function Test-Log4ShellHash{
    Param($hash, $hashKey)
    
    $Ids = Get-Log4ShellIdentifiers

    foreach($id in $ids){
        if($id."$hashKey" -eq $hash){
            $id
        }
    }
}

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
elseif($OutputType -eq "Objects"){

    $Log4ShellResults
}
Stop-Transcript
