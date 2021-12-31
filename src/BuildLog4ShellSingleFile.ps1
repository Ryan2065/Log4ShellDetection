Param(
    $OutPath
)

if([string]::IsNullOrWhiteSpace($OutPath)){
    $OutPath = "$((Get-Item "$PSScriptRoot").Parent.FullName)\Log4ShellDetectionScript.ps1"
}

$Functions = Get-ChildItem "$PSScriptRoot\Detection\Functions" -Filter '*.ps1' | Foreach-Object { Get-Content $_.FullName -Raw }

$FunctionString = $Functions -join "`n"

$ReplaceString = "Get-ChildItem `"`$PSScriptRoot\Functions`" -Filter '*.ps1' | ForEach-Object { . `$_.FullName }"

$BaseScript = Get-Content "$PSScriptRoot\Detection\Log4ShellDetection.ps1" -Raw

$BaseScript.Replace($ReplaceString, $FunctionString) > $OutPath