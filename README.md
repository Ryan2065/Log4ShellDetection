# Log4ShellDetection

Yet another Log4Shell detection script

This is written in PowerShell, targets Windows, and is meant to find Log4Shell vulnerabilities wherever they may be

# How do I use it?

The script is compiled into a single file for easy portability. [Download](https://raw.githubusercontent.com/Ryan2065/Log4ShellDetection/main/Log4ShellDetectionScript.ps1) the latest version and run with it!

You can also get it from the [gallery](https://www.powershellgallery.com/packages/Log4ShellDetectionScript/1.0):

``` PowerShell
Install-Script -Name Log4ShellDetectionScript
```

Once downloaded, just run it with:

```PowerShell
$results = . .\Log4ShellDetectionScript.ps1 -OutputType "Objects"
```

OutputType can be changed based on how it's running - see notes below.

# Why this script?

There are a number of other PowerShell scripts out there, but they have a number of gaps. I stumbled upon a [utility written in Go](https://github.com/hillu/local-log4j-vuln-scanner) that I thought had a great methodoligy. It opens up the Jar files (jar files are just archives) and looks at the hash of the problem .class files. If the hash matches a vulnerable hash, it's marked as detected.

I looked at numerous PowerShell solutions, but they all had some issues as time went on. First off, most PowerShell scripts only look for log4shell in the filename, which misses a whole host of problems. There are some others that will open the jar files and look for the problem .class files, but they just look for them by name. Newer version of log4j that are patched will show up as vulnerable from these scripts also.

So I wrote this script to hopefully get some good in-dept detection on Windows.

# Special thanks
1) Robocopy Search: I had no clue this was possible until I saw it in [Jordan Benzing's script](https://jordantheitguy.com/2021/12/17/find-log4j-with-intune-proactive-remediations/) to search for Log4Shell. 
2) [Hillu Log4j vulnerability Scanner](https://github.com/hillu/local-log4j-vuln-scanner)
3) Everyone else who has shared a script to find these vulnerabilities
4) Reddit / Twitter communities

# How does it work?

1) Searches all drives for *.jar *.war *.ear files
    * Robocopy search is used so it's fairly fast
2) Opens each jar file found and tries to find these files:
    * jndilookup.class
        * This is potentially a vulnerable class file. Hash in the jar is matched against a known list of bad hashes for this file
    * jndimanager.class
        * This is potentially a vulnerable class file. Hash in the jar is matched against a known list of bad hashes for this file
    * socketnode.class
        * This is potentially a vulnerable class file. Hash in the jar is matched against a known list of bad hashes for this file
        * Socketnode is mostly associated with a vulnerability in log4j v1.*
    * manifest.mf
        * This file says what the jar is. If the jar is log4j the script figures out what version and if the version is associated with a CVE. 
        * Note - some remediation steps would remove the .class files that are bad and leave the vulnerable file. This was only ever suggested as a temporary measure, so if no problem class file is found, but the file is a vulnerable log4j file, it's still marked vulnerable
    * *.jar
        * If an embedded jar file is found inside the parent jar file, it'll process this as if it was found on the file system. Many times jar files are packaged together, so if this happened the script will process it still.
3) Outputs results based on Script parameter
    * Script takes a parameter of -OutputType which can be Objects, Host, or Registry
        * Host
            * This will write a summary of all vulnerabilities found to host. Transcripts are running so this will also be logged to the transcript
        * Registry
            * This will write the results to the registry in HKLM:\Software\Log4ShellDetection if running as admin. If not running as admin, will write results to HKCU:\SOFTWARE\Log4ShellDetection
            * Intent is to support applications that can inventory Registry keys for reporting. Can run this script every few days and keep a good inventory of all the vulnerable versions in your environment
        * Objects
            * All results (vulnerable and not vulnerable) are returned from the script.

# I want to look into the source code

If you want to browse the source code, make edits, submit changes, anything, great! The source code is in the folder ```.\src\Detection```.

I did not think it'd be fun to author a huge .ps1 file, so it's broken up into multiple files in the ```.\src``` folder. Once changes are made, simply run the script ```.\src\BuildLog4ShellSingleFile.ps1``` and it will build the single file.

The only other script in this repo that's not obvious is ```Search-DownloadedJars.ps1```. I wrote this file to scrape Maven (where log4j is stored) for all the vulnerable .jar files. Once downloaded, the script opens them up and gathers identifying information. It'll compile all the data as JSON and then it just needs to be pasted into ```Get-Log4ShellIdentifiers.ps1``` where the existing json is. 

# I have an issue!

Great, glad someone's using the script. Post the issue in GitHub and I'll take a look when I can.

# Known issues

1) One known issue that I came across when testing - If there's only a match on .class files and the script can't find the version in the manifest, it will report back as multiple versions. So if you see a .jar and the version reporeted of log4j is a comma separated list, that's why. It found a class that's vulnerable, and is associated with one of those versions, but was not able to narrow it down. It should only ever return 2 or 3 versions this way if there's a match.