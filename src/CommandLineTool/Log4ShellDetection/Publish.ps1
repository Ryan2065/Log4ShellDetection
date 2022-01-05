Push-Location "$PSScriptRoot\Log4ShellDetection"

$RIDs = @(
    'win-x64',
    'win-x86',
    'linux-x64',
    'osx-x64'
    )

foreach($rid in $rids){
    cmd /c dotnet publish -r $rid -c Release --self-contained true -o "$PSScriptRoot\Log4ShellDetection\bin\Publish\$rid"
}

Pop-Location