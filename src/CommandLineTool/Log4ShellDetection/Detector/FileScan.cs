using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Detector
{
    public class FileScan : IDisposable
    {
        private ScanResult _scanResult;
        private List<string> _scannedChildJars = new List<string>();
        private ScanResult _socketNodeResult = new ScanResult();
        private bool _jmsAppender = false;
        private bool disposedValue;


        public ScanResult ScanFile(string filePath)
        {
            _scanResult = new ScanResult(filePath);
            using(var zip = ZipFile.OpenRead(filePath))
            {
                foreach(var entry in zip.Entries)
                {
                    ProcessEntry(entry);
                }
            }
            if (_jmsAppender)
            {
                _scanResult.AddCVEs(_socketNodeResult.CVEs);
                foreach(var c in _socketNodeResult.DetectedVulnerableClass)
                {
                    _scanResult.AddClass(c);
                }
                foreach (var v in _socketNodeResult.DetectedVersion)
                {
                    _scanResult.AddVersion(v);
                }
                if (_socketNodeResult.EmbeddedJarVulnerable)
                {
                    _scanResult.EmbeddedJarVulnerable = true;
                }
            }
            _scanResult.Vulnerable = _scanResult.CVEs.Count > 0;
            return _scanResult;
        }
        private string SHA256HashStream(Stream stream)
        {
            using(var sha256 = SHA256.Create())
            {
                return BitConverter.ToString(sha256.ComputeHash(stream)).ToLowerInvariant().Replace("-", "");
            }
        }
        private void ProcessEntry(ZipArchiveEntry entry, bool embeddedJar = false)
        {
            var entryLowerName = entry.Name.ToLower();
            if (entryLowerName.Contains("jndilookup"))
            {
                using (var stream = entry.Open())
                {
                    foreach(var result in Log4ShellIdentifiers.CheckJdniLookupHash(SHA256HashStream(stream)))
                    {
                        _scanResult.AddCVEs(result.CVEs);
                        _scanResult.AddClass(entry.Name);
                        _scanResult.AddVersion(result.Version);
                        if (embeddedJar)
                        {
                            _scanResult.EmbeddedJarVulnerable = true;
                        }
                    }
                }
            }
            else if (entryLowerName.Contains("jndimanager"))
            {
                using (var stream = entry.Open())
                {
                    foreach (var result in Log4ShellIdentifiers.CheckJdniManagerHash(SHA256HashStream(stream)))
                    {
                        _scanResult.AddCVEs(result.CVEs);
                        _scanResult.AddClass(entry.Name);
                        _scanResult.AddVersion(result.Version);
                        if (embeddedJar)
                        {
                            _scanResult.EmbeddedJarVulnerable = true;
                        }
                    }
                }
            }
            else if (entryLowerName.Contains("socketnode"))
            {
                using (var stream = entry.Open())
                {
                    foreach (var result in Log4ShellIdentifiers.CheckSocketNodeHash(SHA256HashStream(stream)))
                    {
                        _socketNodeResult.AddCVEs(result.CVEs);
                        _socketNodeResult.AddClass(entry.Name);
                        _socketNodeResult.AddVersion(result.Version);
                        if (embeddedJar)
                        {
                            _socketNodeResult.EmbeddedJarVulnerable = true;
                        }
                    }
                }
            }
            else if (entryLowerName.Contains("jmsappender"))
            {
                _jmsAppender = true;
            }
            else if (entryLowerName == "manifest.mf")
            {
                using (var stream = entry.Open())
                {
                    using (var streamReader = new StreamReader(stream))
                    {
                        foreach (var result in Log4ShellIdentifiers.CheckManifestMf(streamReader))
                        {
                            _scanResult.AddCVEs(result.CVEs);
                            _scanResult.AddVersion(result.Version);
                            if (embeddedJar)
                            {
                                _scanResult.EmbeddedJarVulnerable = true;
                            }
                        }
                    }
                }
            }
            else if (entryLowerName.EndsWith(".jar"))
            {
                string jarHash = "";
                using (var stream = entry.Open())
                {
                    jarHash = SHA256HashStream(stream);
                }
                if (_scannedChildJars.Contains(jarHash))
                {
                    // I don't know if infinite recursion can happen in jar files
                    // and I don't want to find out
                    return;
                }
                _scannedChildJars.Add(jarHash);
                using(var stream = entry.Open())
                {
                    var zip = new ZipArchive(stream, ZipArchiveMode.Read);
                    foreach(var e in zip.Entries)
                    {
                        ProcessEntry(e, true);
                    }
                }
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                _scanResult = null;
                _scannedChildJars = null;
                _socketNodeResult = null;
                disposedValue = true;
            }
        }


        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    
    public class ScanResult
    {
        public ScanResult() { }
        public ScanResult(string filePath)
        {
            FilePath = filePath;
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    FileMD5Hash = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }
        public string FileMD5Hash { get; set; }
        public string FilePath { get; set; }
        public bool Vulnerable { get; set; }
        public bool EmbeddedJarVulnerable { get; set; }
        public List<string> CVEs { get; set; } = new List<string>();
        public List<string> DetectedVulnerableClass { get; set; } = new List<string>();
        public List<string> DetectedVersion { get; set; } = new List<string>();

        public void AddCVEs(List<string> cves)
        {
            foreach(var c in cves)
            {
                if (!CVEs.Contains(c))
                {
                    CVEs.Add(c);
                }
            }
        }
        public void AddClass(string c)
        {

            if (!DetectedVulnerableClass.Contains(c))
            {
                DetectedVulnerableClass.Add(c);
            }

        }
        public void AddVersion(string v)
        {
            if (!DetectedVulnerableClass.Contains(v))
            {
                DetectedVulnerableClass.Add(v);
            }
        }
    }
}
