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

