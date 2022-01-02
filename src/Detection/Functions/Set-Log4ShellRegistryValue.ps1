Function Set-Log4ShellRegistryValue{
    Param(
        [Microsoft.Win32.RegistryKey]$Key,
        [string]$Name,
        [object]$value
    )
    if($null -eq $value){
        $value = ""
    }
    $Key.SetValue($Name, $value)
}