Function Test-Log4ShellAlreadyProcessed {
    Param($Hash)

    foreach($existingResult in $Global:Log4ShellResults){
        if($existingResult.FileHash -eq $Hash){
            return $existingResult
        }
    }
}