using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Detector
{
    public class FileSearch
    {
        public List<string> ExcludePaths { get; set; } = new List<string>();
        public ConcurrentQueue<string> QueueVulnerableFiles { get; set; } = new ConcurrentQueue<string>();

        private ConcurrentQueue<string> _queuePaths = new ConcurrentQueue<string>();
        private List<Task> _taskList = new List<Task>();

        public bool ShouldScan(string pathToValidate)
        {
            if (string.IsNullOrWhiteSpace(pathToValidate))
            {
                return false;
            }
            foreach(var e in ExcludePaths)
            {
                if(pathToValidate.StartsWith(e, StringComparison.InvariantCultureIgnoreCase))
                {
                    Console.WriteLine($"Excluding {pathToValidate} from scan");
                    return false;
                }
            }
            return true;
        }

        private void HandleDirectorySearchError(Exception ex, string pathThatErrored)
        {

        }
        public void SearchQueue()
        {
            while (_queuePaths.Count > 0)
            {
                if (_queuePaths.TryDequeue(out string path))
                {
                    try
                    {
                        foreach (string subDir in Directory.EnumerateDirectories(path))
                        {
                            if (ShouldScan(subDir))
                            {
                                _queuePaths.Enqueue(subDir);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        HandleDirectorySearchError(ex, path);
                    }
                    try
                    {
                        foreach (string file in Directory.GetFiles(path, "*ar"))
                        {
                            if (file.EndsWith(".jar", StringComparison.InvariantCultureIgnoreCase)
                            || file.EndsWith(".war", StringComparison.InvariantCultureIgnoreCase)
                            || file.EndsWith(".war", StringComparison.InvariantCultureIgnoreCase))
                            {
                                Console.WriteLine($"Will analyze java file {file}");
                                QueueVulnerableFiles.Enqueue(file);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        HandleDirectorySearchError(ex, path);
                    }
                }
            }
        }
        public void StartThreadedSearch(int numberOfThreads = 8)
        {
            int taskCount = _taskList.Count;
            while(taskCount < numberOfThreads)
            {
                _taskList.Add(Task.Run(() => SearchQueue()));
                taskCount++;
            }
            WaitTasks();
        }
        public void WaitTasks()
        {
            Task.WaitAny(_taskList.ToArray());
            for (int i = _taskList.Count - 1; i > -1; i--)
            {
                if (_taskList[i].IsCompleted)
                {
                    _taskList[i].Dispose();
                    _taskList.RemoveAt(i);
                }
            }
            if (!_queuePaths.IsEmpty)
            {
                StartThreadedSearch();                
            }
            else if (_taskList.Count > 0)
            {
                WaitTasks();
            }
            
        }
        public Task GetRecursiveFiles(string filePath)
        {
            _queuePaths.Enqueue(filePath);
            return Task.Run(() => StartThreadedSearch());
        }
        public IEnumerable<string> GetRootDrives()
        {
            foreach(var drive in System.IO.DriveInfo.GetDrives())
            {
                yield return drive.RootDirectory.FullName;
            }
            
        }
    }
    
}
