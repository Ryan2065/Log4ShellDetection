# Log4ShellDetection

Yet another Log4Shell detection script

This is written in PowerShell, targets Windows, and is meant to find Log4Shell vulnerabilities wherever they may be

# CVEs detected

## How I got the CVE information

I wrote a script to scrape Maven (site where Log4J is hosted) Log4J versions and compile which ones were vulnerable to which CVEs as direct vulnerabilities or indrect vulnerabilities. This script also downloaded those Log4J versions and looked for the problem class files socketnode.class, jdnimanager.class, or JndiLookup.class. A SHA256 hash of each file was taken and saved for use in the detection script. With those hashes, we can scan any jar file and know if it has vulnerable code associated with one of the Log4Shell CVEs. 

## CVE Rules

* CVE-2021-44228
    * Description: First Log4Shell vulnerability that allows for remote code execution
    * Rules: 
        * Flagged if any jar uses jdnimanager.class or jdnilookup.class from vulnerable Log4J versions
        * Flagged if the jar file is log4j from a version that's vulnerable
* CVE-2021-45046
    * Description: Originally just a denial of service vulnerability, was then upgraded to remote code exection that still applied to Log4J 2.15 (the latest fixed version at the time)
    * Rules:
        * Flagged if any jar uses jdnimanager.class or jdnilookup.class from vulnerable Log4J versions
        * Flagged if the jar file is log4j from a version that's vulnerable
* CVE-2021-45105
    * Description: Denial of service vulnerability exploitable in non-default configurations
    * Rules:
        * Flagged if any jar uses jdnimanager.class or jdnilookup.class from vulnerable Log4J versions
        * Flagged if the jar file is log4j from a version that's vulnerable
* CVE-2021-4104
    * CVE associated with Log4J v1.*
    * Detected based on socketnode.class file in the jar
    * Log4J v1.* is only vulnerable if configured with JMSAppender. As of v1.3 of the detection script, we only flag Log4J v1 as vulnerable if JMSAppender is also there.
* CVE-2021-44832
    * Description: Remote code execution bug, but requires the attacker to have control of the Log4J config. Much harder to exploit, but still a remote code execution CVE.
    * CVE associated with Log4J v2.* less than 2.17.1
    * Detected based on jdnimanager.class or jdnilookup.class from vulnerable log4j versions


# How do I use it?

The script is compiled into a single file for easy portability. [Download](https://raw.githubusercontent.com/Ryan2065/Log4ShellDetection/main/Log4ShellDetectionScript.ps1) the latest version and run with it!

You can also get it from the [gallery](https://www.powershellgallery.com/packages/Log4ShellDetectionScript):

``` PowerShell
Install-Script -Name Log4ShellDetectionScript
```

Once downloaded, just run it with:

```PowerShell
$results = . .\Log4ShellDetectionScript.ps1 -OutputType "Objects"
```

OutputType can be changed based on how it's running - see notes below.

If you want to pick the CVEs it searches for, run it with:

```PowerShell
$results = . .\Log4ShellDetectionScript.ps1 -OutputType "Objects" -CVEsToDetect @("CVE-2021-4104")
```

The above will only search for CVE-2021-4104 instead of all 4 CVEs. 

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

# Versions

* 1.0 - Initial release
* 1.1 - Bug fix - recursive jar search works properly now
* 1.2 - CVE-2021-4104 only triggers in Log4j v1 if the class JMSAppender exists
* 1.2.1 - Added parameter to specify the CVE you want to search for on the main script. Default is all 4, but can narrow down to one or two
* 1.2.2 - Added parameter to scan specific files instead of the entire drive
* 1.3.0 - Made it write to 64-bit registry from 32-bit processes on 64-bit machines
    * Added JSON as output type
    * Added parameter for OutputAll - this will output vulnerable and non-vulnerable objects (can parse which is which through the Vulnerable property)
    * Added Transcript parameter to enable / disable transcripts on the scan
* 1.3.1 - Made File parameter and CVE parameter accept comma separated strings or arrays
    * Added help
    * Removed custom class for results - when rerunning in the same Posh session would cause issues
* 1.4.0 - New release with feedback incorporated!
    * New output type - CountVulnerable - will simply output the number of vulnerable files
    * New output type - Silent
    * New Parameter: TatooRegistry - allows you to scan with a different output type (like Host) and still have results put in the registry
    * New Parameter: FoldersToScan - Can give a list of folders to scan. Accepts either an array or comma separated list
    * New Parameter: Transcript - Will enable / disable the transcript
    * New Parameter: LowProcessPriority - Sets the Posh process to low processor priority to not take up too many resources
    * New CVE Detection: CVE-2021-44832 - will now detect the latest RCE for Log4J
    * Transcript no longer outputs information if it's enabled. 
    * Manifest.mf detection has been changed to a file hash detection - was using this to determine which version of Log4J the file is, even if someone removed the JDNI files. Previously this would cause false positives. This should be resolved.
    * Search change - Search no longer uses robocopy so this should work on Linux also
* 1.4.1 - Added parameter SkipNetworkDrives - On a Windows system will only scan local drives. Uses Win32_LogicalDisk.DriveType = 3
