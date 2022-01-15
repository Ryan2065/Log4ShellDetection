Push-Location "$PSScriptRoot\Log4ShellDetection"

$RIDs = @(
    '',
    'win-x86',
    'linux-x64',
    'osx-x64'
    )

#Windows x64
#cmd /c dotnet publish -r win-x64 -c Release --self-contained true -o "$PSScriptRoot\Log4ShellDetection\bin\Publish\win-x64"

#cmd /c "$PSScriptRoot\Log4ShellDetection\bin\Publish\win-x64\Log4ShellDetection.exe"

#Linux x64

#c/users/ryan2/onedrive/code/log4shelldetection/src/commandlinetool/log4shelldetection/log4shelldetection

$LinuxPath = "/mnt/" + $PSScriptRoot.ToLower().Replace(":","").Replace("\","/") + "/Log4ShellDetection"

$shScript = @()
$shScript += "cd $LinuxPath"
$shScript += "dotnet publish -r linux-x64 -c Release --self-contained true -o $LinuxPath/bin/publish/linux-x64"
$shScript += "cd $LinuxPath/bin/publish/linux-x64"
$shScript += "strip $linuxpath/bin/publish/linux-x64/log4shelldetection"
$shScript += ""

$FilePath = "$PSScriptRoot\Log4ShellDetection\bin\buildlinux.sh"

if(Test-Path $FilePath ){
    Remove-Item $FilePath -Force
}

$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
[System.IO.File]::WriteAllLines($FilePath, ( $shScript -join "`n" ), $Utf8NoBomEncoding)

cmd /c wsl sh "$LinuxPath/bin/buildlinux.sh"

cmd /c wsl "$linuxpath/bin/publish/linux-x64/log4shelldetection" -ep /mnt/c
Pop-Location