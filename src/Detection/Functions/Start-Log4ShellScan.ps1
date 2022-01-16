Function Start-Log4ShellScan{
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$FileToScan
    )
    process{
        try{
            if([string]::IsNullOrWhiteSpace($FileToScan)){ return }
            
            $result = Search-Log4Shell -Path $FileToScan
            $resultAdded = $false
            if($null -eq $result){
                Write-Warning "No result returned for file $FileToScan"
            }
            elseif($result.GetType().IsArray){
                foreach($r in $result){
                    if($r.GetType().Name -eq 'PSCustomObject'){
                        $Global:Log4ShellResults.Add($r)
                        $resultAdded = $true
                    }
                }
                if(-not $resultAdded){
                    Write-Warning "Unexpected result from file $($FileToScan) - could not process"
                }
            }
            elseif($result.GetType().Name -eq 'PSCustomObject'){
                $Global:Log4ShellResults.Add($result)
            }
            else{
                Write-Warning "Unexpected result from file $($FileToScan) - could not process"
            }
        }
        catch{
            if($_.Exception.Message -eq 'Exception calling "OpenRead" with "1" argument(s): "End of Central Directory record could not be found."'){
                Write-Warning "Error processing jar file $($FileToScan) - appears corrupt`n$($_.Exception.Message)"
            }
            else{
                Write-Warning "Error processing jar file $($FileToScan)`n$($_.Exception.Message)"
            }
        }
    }
    
}