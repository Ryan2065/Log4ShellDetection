Function Test-Log4ShellHash{
    Param($hash, $hashKey)
    
    $Ids = Get-Log4ShellIdentifiers

    foreach($id in $ids){
        if($id."$hashKey" -eq $hash){
            $id
        }
    }
}
