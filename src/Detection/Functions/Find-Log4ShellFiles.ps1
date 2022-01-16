Function Find-Log4ShellFiles {
    [CmdletBinding()]
    Param(
        $root
    )
    $DirectoriesToScan = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
    $FindDirectoriesRS = [runspacefactory]::CreateRunspace()
    $null = $FindDirectoriesRS.Open()
    $null = $FindDirectoriesRS.SessionStateProxy.SetVariable('DirectoriesToScan', $DirectoriesToScan)
    $FindDirectoriesPS = [powershell]::Create()
    $FindDirectoriesPS.Runspace = $FindDirectoriesRS

    $null = $FindDirectoriesPS.AddScript({
        Param($rootDir)
        Function GetChildDirs($parentDir){
            $childDirectories = [System.IO.Directory]::EnumerateDirectories($parentDir)
            foreach($c in $childDirectories){
                $null = $DirectoriesToScan.Enqueue($c)
                try{
                    GetChildDirs $c
                } catch {
                    # ignore errors for now
                }
            }
        }
        try{
            $null = $DirectoriesToScan.Enqueue($rootDir)
            GetChildDirs $rootDir
        }
        catch {
            #ignoring errors for now
        }
    })
    $null = $FindDirectoriesPS.AddParameter('rootDir', $root)
    $FindDirectoriesPSInvoke = $FindDirectoriesPS.BeginInvoke()

    $Runspaces = @()

    $FoundFiles = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
    $ControlHash = [hashtable]::Synchronized(@{})
    $ControlHash.DirScannerRunning = $true
    for($i = 0; $i -lt 8; $i++){
        $FileSearchRS = [runspacefactory]::CreateRunspace()
        $null = $FileSearchRS.Open()
        
        $null = $FileSearchRS.SessionStateProxy.SetVariable('DirectoriesToScan', $DirectoriesToScan)
        $null = $FileSearchRS.SessionStateProxy.SetVariable('FoundFiles', $FoundFiles)
        $null = $FileSearchRS.SessionStateProxy.SetVariable('ControlHash', $ControlHash)
        $FileSearchPS = [powershell]::Create()
        $FileSearchPS.Runspace = $FileSearchRS
        $null = $FileSearchPS.AddScript({
            while($ControlHash.DirScannerRunning -or ($DirectoriesToScan.Count -gt 0)){
                if($DirectoriesToScan.Count -eq 0){
                    Start-Sleep -Milliseconds 500
                }
                $outPath = ""
                while($DirectoriesToScan.TryDequeue([ref]$outPath)){
                    try{
                        $getFiles = [System.IO.Directory]::GetFiles($outPath, '*ar')
                        foreach($f in $getFiles){
                            if($f.EndsWith('.jar', [System.StringComparison]::InvariantCultureIgnoreCase) -or
                            $f.EndsWith('.war', [System.StringComparison]::InvariantCultureIgnoreCase) -or
                            $f.EndsWith('.ear', [System.StringComparison]::InvariantCultureIgnoreCase)
                            ){
                                $null = $FoundFiles.Enqueue($f)
                            }
                        }
                    }
                    catch{
                        # Ignoring errors for now
                    }
                }
            }
        })
        $FileSearchPSInvoke = $FileSearchPS.BeginInvoke()
        $Runspaces += @(@{
            'PSCommand' = $FileSearchPS
            'Invoke' = $FileSearchPSInvoke
            'Runspace' = $FileSearchRS
        })
    }

    while(-not $FindDirectoriesPSInvoke.IsCompleted){
        Start-Sleep -Milliseconds 500
        $result = ""
        while($FoundFiles.TryDequeue([ref]$result)){
            Write-Output $result
        }
    }

    $null = $FindDirectoriesPS.Stop()
    $null = $FindDirectoriesPS.Dispose()
    $null = $FindDirectoriesRS.Dispose()

    $ControlHash.DirScannerRunning = $false

    while($Runspaces.Invoke.IsCompleted -contains $false){
        Start-Sleep -Milliseconds 500
        $result = ""
        while($FoundFiles.TryDequeue([ref]$result)){
            Write-Output $result
        }
    }

    foreach($item in $Runspaces){
        $null = $item.PSCommand.Stop()
        $null = $item.PSCommand.Dispose()
        $null = $item.Runspace.Dispose()
    }
    $Runspaces = $null
    <#
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
    }#>
}

