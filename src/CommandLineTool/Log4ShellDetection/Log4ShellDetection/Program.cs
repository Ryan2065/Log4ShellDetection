using System.CommandLine;

var pathsOption = new Option<string[]>(new[] { "--paths", "-p" }, description: "Path or paths to scan - if null scans everything");
var excludeOption = new Option<string[]>(new[] { "--excludepath", "-ep" }, description: "Paths to exclude from the scan");
var verboseOption = new Option<string[]>(new[] { "--excludepath", "-ep" }, description: "Paths to exclude from the scan");
var cmd = new RootCommand { pathsOption, excludeOption };
cmd.SetHandler((string[] paths, string[] excludePaths) => 
{
    Log4ShellDetection.RunDetector.Start(paths, excludePaths);
}, pathsOption, excludeOption);

return cmd.Invoke(args);

