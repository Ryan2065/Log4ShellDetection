
using Detector;

var fileSearch = new Detector.FileSearch();
var rootDrives = fileSearch.GetRootDrives();

int scannedFiles = 0;
int vulnerableFileCount = 0;
List<ScanResult> scanResults = new List<ScanResult>();
foreach(var rootDrive in rootDrives)
{
    foreach(var f in fileSearch.GetRecursiveFiles(rootDrive))
    {
        using (var searcher = new Detector.FileScan())
        {
            var result = searcher.ScanFile(f);
            scanResults.Add(result);
            if (result.Vulnerable)
            {
                vulnerableFileCount++;
            }
            scannedFiles++;
        }
    }
}

Console.WriteLine($"Finished scanning {scannedFiles} files - found {vulnerableFileCount} vulnerabilities");