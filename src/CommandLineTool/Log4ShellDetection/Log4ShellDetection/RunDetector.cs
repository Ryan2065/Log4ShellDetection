using Detector;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Log4ShellDetection
{
    public static class RunDetector
    {
        private static FileSearch fileSearch = new Detector.FileSearch();
        private static List<ScanResult> scanResults = new List<ScanResult>();
        private static List<string> GetScanPaths(string[]? paths, string[]? excludePaths)
        {
            List<string> scanPaths = new List<string>();
            if (excludePaths != null && excludePaths.Count() > 0)
            {
                fileSearch.ExcludePaths.AddRange(excludePaths);
            }

            if (paths != null && paths.Count() > 0)
            {
                scanPaths.AddRange(paths);
            }
            else
            {
                var rootDrives = fileSearch.GetRootDrives();
                foreach (var rd in rootDrives)
                {
                    if (fileSearch.ShouldScan(rd))
                    {
                        scanPaths.Add(rd);
                    }
                }
            }
            return scanPaths;
        }
        private static void ScanPath(string scanPath)
        {
            var searcherTask = fileSearch.GetRecursiveFiles(scanPath);
            while (!searcherTask.IsCompleted)
            {
                Thread.Sleep(50);
                while (!fileSearch.QueueVulnerableFiles.IsEmpty)
                {
                    if (fileSearch.QueueVulnerableFiles.TryDequeue(out string? f))
                    {
                        if (!string.IsNullOrWhiteSpace(f))
                        {
                            using (var searcher = new Detector.FileScan())
                            {
                                Console.WriteLine($"Found file {f} - scanning for vulnerabilities");
                                var result = searcher.ScanFile(f);
                                scanResults.Add(result);
                                if (result.Vulnerable)
                                {
                                    vulnerableFileCount++;
                                }
                                scannedFiles++;
                                Console.WriteLine("Scan complete");
                            }
                        }
                    }
                }
            }
        }
        public static void Start(string[]? paths, string[]? excludePaths)
        {
            var scanPaths = GetScanPaths(paths, excludePaths);
            
            
            int scannedFiles = 0;
            int vulnerableFileCount = 0;
            
            foreach (var scanPath in scanPaths)
            {
                
            }

            Console.WriteLine($"Finished scanning {scannedFiles} files - found {vulnerableFileCount} vulnerabilities");
        }
    }
}
