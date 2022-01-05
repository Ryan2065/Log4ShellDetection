using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Detector
{
    public class FileSearch
    {
        private ConcurrentQueue<string> _queuePaths = new ConcurrentQueue<string>();
        private ConcurrentQueue<string> _queueVulnerableFiles = new ConcurrentQueue<string>();
        private List<Task> _taskList = new List<Task>();
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
                            _queuePaths.Enqueue(subDir);
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
                                _queueVulnerableFiles.Enqueue(file);
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
        public IEnumerable<string> StartThreadedSearch(int numberOfThreads = 8)
        {
            int taskCount = _taskList.Count;
            while(taskCount < numberOfThreads)
            {
                _taskList.Add(Task.Run(() => SearchQueue()));
                taskCount++;
            }
            foreach(var s in WaitTasks())
            {
                yield return s;
            }
        }
        public IEnumerable<string> WaitTasks()
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
            if(!_queuePaths.IsEmpty)
            {
                foreach(var s in StartThreadedSearch())
                {
                    yield return s;
                }
            }
            else if (_taskList.Count > 0)
            {
                foreach (var s in WaitTasks())
                {
                    yield return s;
                }
            }
            while (!_queueVulnerableFiles.IsEmpty)
            {
                if(_queueVulnerableFiles.TryDequeue(out string result))
                {
                    yield return result;
                }
            }
        }
        public IEnumerable<string> GetRecursiveFiles(string filePath)
        {
            _queuePaths.Enqueue(filePath);
            foreach (var s in StartThreadedSearch())
            {
                yield return s;
            }
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
