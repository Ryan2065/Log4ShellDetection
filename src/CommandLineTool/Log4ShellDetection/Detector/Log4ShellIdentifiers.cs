using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Detector
{
    public static class Log4ShellIdentifiers
    {
        private static List<Log4ShellIdentifier> Identifiers = new List<Log4ShellIdentifier>();
        public static void LoadList()
        {
            #region GeneratedCode
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.3.2",
                JdniLookupHash = "7f0add9055958365137a8cc7a90969a43c44b20280323bdac718c1ff3795beb8",
                JdniManagerHash = "89535e03625d7ed5074d12eab85a9b27a643fcaf9ed62b152371d209ee90ce80",
                ReleaseVersionString = "Log4jReleaseVersion: 2.3.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.12.4",
                JdniLookupHash = "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
                JdniManagerHash = "a954ff8c69d43a40dac017ec01ecc56f6c39d9122cb3c388abbe89b975a6fe95",
                ReleaseVersionString = "Log4jReleaseVersion: 2.12.4",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "2.17.1",
                JdniLookupHash = "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
                JdniManagerHash = "3588a6aaf84fa79215a1cc5d12dee69413b8772656c73bdf26ef35df713b1091",
                ReleaseVersionString = "Log4jReleaseVersion: 2.17.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.3.1",
                JdniLookupHash = "0ad99a95ff637fc966fc4ce5fe1f9e78d3b24b113282f9990b95a6fde3383d9c",
                JdniManagerHash = "6ce4436eca5edc852d375cbc831cd652b80fc16f6238cd2b22bd115b3735460e",
                ReleaseVersionString = "Log4jReleaseVersion: 2.3.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.12.3",
                JdniLookupHash = "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
                JdniManagerHash = "f04dd01860bb32750a47fc3f6b29a41b4dd04736fadf0fd63c4f1909d845afd2",
                ReleaseVersionString = "Log4jReleaseVersion: 2.12.3",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "2.17.0",
                JdniLookupHash = "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
                JdniManagerHash = "9c2a6ea36c79fa23da59cc0f6c52c07ce54ca145ddd654790a3116d2b24de51b",
                ReleaseVersionString = "Log4jReleaseVersion: 2.17.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.12.2",
                JdniLookupHash = "febbc7867784d0f06934fec59df55ee45f6b24c55b17fff71cc4fca80bf22ebb",
                JdniManagerHash = "b1960d63a3946f9e16e1920624f37c152b58b98932ed04df99ed5d9486732afb",
                ReleaseVersionString = "Log4jReleaseVersion: 2.12.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.16.0",
                JdniLookupHash = "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                JdniManagerHash = "5210e6aae7dd8a61cd16c56937c5f2ed43941487830f46e99d0d3f45bfa6f953",
                ReleaseVersionString = "Log4jReleaseVersion: 2.16.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-4104" },
                Version = "2.15.0",
                JdniLookupHash = "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                JdniManagerHash = "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e",
                ReleaseVersionString = "Log4jReleaseVersion: 2.15.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.14.1",
                JdniLookupHash = "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                JdniManagerHash = "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.14.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.14.0",
                JdniLookupHash = "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                JdniManagerHash = "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.14.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.13.3",
                JdniLookupHash = "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                JdniManagerHash = "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078",
                ReleaseVersionString = "Log4jReleaseVersion: 2.13.3",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.13.2",
                JdniLookupHash = "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                JdniManagerHash = "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078",
                ReleaseVersionString = "Log4jReleaseVersion: 2.13.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.13.1",
                JdniLookupHash = "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                JdniManagerHash = "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078",
                ReleaseVersionString = "Log4jReleaseVersion: 2.13.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.13.0",
                JdniLookupHash = "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                JdniManagerHash = "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078",
                ReleaseVersionString = "Log4jReleaseVersion: 2.13.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.12.1",
                JdniLookupHash = "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
                JdniManagerHash = "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de",
                ReleaseVersionString = "Log4jReleaseVersion: 2.12.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.12.0",
                JdniLookupHash = "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
                JdniManagerHash = "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de",
                ReleaseVersionString = "Log4jReleaseVersion: 2.12.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.11.2",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.11.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228" },
                Version = "2.11.1",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.11.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.11.0",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.11.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.10.0",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.10.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.9.1",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.9.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.9.0",
                JdniLookupHash = "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                JdniManagerHash = "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
                ReleaseVersionString = "Log4jReleaseVersion: 2.9.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.8.2",
                JdniLookupHash = "d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15",
                JdniManagerHash = "764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407",
                ReleaseVersionString = "Log4jReleaseVersion: 2.8.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.8.1",
                JdniLookupHash = "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
                JdniManagerHash = "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32",
                ReleaseVersionString = "Log4jReleaseVersion: 2.8.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.8",
                JdniLookupHash = "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
                JdniManagerHash = "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32",
                ReleaseVersionString = "Log4jReleaseVersion: 2.8",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.7",
                JdniLookupHash = "cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae",
                JdniManagerHash = "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32",
                ReleaseVersionString = "Log4jReleaseVersion: 2.7",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.6.2",
                JdniLookupHash = "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                JdniManagerHash = "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246",
                ReleaseVersionString = "Log4jReleaseVersion: 2.6.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.6.1",
                JdniLookupHash = "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                JdniManagerHash = "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246",
                ReleaseVersionString = "Log4jReleaseVersion: 2.6.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.6",
                JdniLookupHash = "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                JdniManagerHash = "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246",
                ReleaseVersionString = "Log4jReleaseVersion: 2.6",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.5",
                JdniLookupHash = "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                JdniManagerHash = "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7",
                ReleaseVersionString = "Log4jReleaseVersion: 2.5",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.4.1",
                JdniLookupHash = "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                JdniManagerHash = "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7",
                ReleaseVersionString = "Log4jReleaseVersion: 2.4.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.4",
                JdniLookupHash = "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                JdniManagerHash = "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7",
                ReleaseVersionString = "Log4jReleaseVersion: 2.4",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.3",
                JdniLookupHash = "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                JdniManagerHash = "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c",
                ReleaseVersionString = "Log4jReleaseVersion: 2.3",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.2",
                JdniLookupHash = "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                JdniManagerHash = "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c",
                ReleaseVersionString = "Log4jReleaseVersion: 2.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.1",
                JdniLookupHash = "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                JdniManagerHash = "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c",
                ReleaseVersionString = "Log4jReleaseVersion: 2.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0.2",
                JdniLookupHash = "9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0.2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0.1",
                JdniLookupHash = "964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0.1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0",
                JdniLookupHash = "fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0-rc2",
                JdniLookupHash = "a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-rc2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0-rc1",
                JdniLookupHash = "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-rc1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-45046", "CVE-2021-44228", "CVE-2021-4104" },
                Version = "2.0-beta9",
                JdniLookupHash = "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta9",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta8",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta8",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta7",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta7",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta6",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta6",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta5",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta5",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta4",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta4",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta3",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta3",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta2",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-beta1",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-beta1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-alpha2",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-alpha2",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-45105", "CVE-2021-4104" },
                Version = "2.0-alpha1",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "Log4jReleaseVersion: 2.0-alpha1",
                SocketNodeHash = "",
                ImplementationVersionString = ""
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.17",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74",
                ImplementationVersionString = "Implementation-Version: 1.2.17"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.16",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46",
                ImplementationVersionString = "Implementation-Version: 1.2.16"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.15",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4",
                ImplementationVersionString = "Implementation-Version: 1.2.15"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.14",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7",
                ImplementationVersionString = "Implementation-Version: 1.2.14"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.13",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7",
                ImplementationVersionString = "Implementation-Version: 1.2.13"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.9",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
                ImplementationVersionString = "Implementation-Version: 1.2.9"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.12",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c",
                ImplementationVersionString = "Implementation-Version: 1.2.12"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.11",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6",
                ImplementationVersionString = "Implementation-Version: 1.2.11"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.8",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9",
                ImplementationVersionString = "Implementation-Version: 1.2.8"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.7",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
                ImplementationVersionString = "Implementation-Version: 1.2.7"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.6",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0",
                ImplementationVersionString = "Implementation-Version: 1.2.6"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.5",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a",
                ImplementationVersionString = "Implementation-Version: 1.2.5"
            });
            Identifiers.Add(new Log4ShellIdentifier()
            {
                CVEs = new List<string>() { "CVE-2021-4104" },
                Version = "1.2.4",
                JdniLookupHash = "",
                JdniManagerHash = "",
                ReleaseVersionString = "",
                SocketNodeHash = "6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d",
                ImplementationVersionString = "Implementation-Version: 1.2.4"
            });

            #endregion
        }
        public static IEnumerable<Log4ShellIdentifier> CheckJdniLookupHash(string hash)
        {
            if(Identifiers.Count == 0)
            {
                LoadList();
            }
            foreach(var id in Identifiers)
            {
                if(id.JdniLookupHash == hash)
                {
                    yield return id;
                }
            }
        }
        public static IEnumerable<Log4ShellIdentifier> CheckJdniManagerHash(string hash)
        {
            if (Identifiers.Count == 0)
            {
                LoadList();
            }
            foreach (var id in Identifiers)
            {
                if (id.JdniManagerHash == hash)
                {
                    yield return id;
                }
            }
        }
        public static IEnumerable<Log4ShellIdentifier> CheckSocketNodeHash(string hash)
        {
            if (Identifiers.Count == 0)
            {
                LoadList();
            }
            foreach (var id in Identifiers)
            {
                if (id.SocketNodeHash == hash)
                {
                    yield return id;
                }
            }
        }
        public static IEnumerable<Log4ShellIdentifier> CheckManifestMf(StreamReader manifestFile)
        {
            if (Identifiers.Count == 0)
            {
                LoadList();
            }
            List<string> fileLines = new List<string>();
            bool releaseVersion = false;
            bool implementationVersion = false;
            while(manifestFile.Peek() >= 0)
            {
                string line = manifestFile.ReadLine();
                if (!string.IsNullOrWhiteSpace(line))
                {
                    fileLines.Add(line.Trim());
                    if (line.ToLower().Contains("log4jreleaseversion"))
                    {
                       releaseVersion = true;
                    }
                    else if (line.ToLower().Contains("implementation-title: log4j"))
                    {
                        implementationVersion = true;
                    }
                }
                
            }
            if (releaseVersion)
            {
                foreach (var id in Identifiers)
                {
                    foreach(var line in fileLines)
                    {
                        if(id.ReleaseVersionString == line)
                        {
                            yield return id;
                        }
                    }
                }
            }
            else if (implementationVersion)
            {
                foreach (var id in Identifiers)
                {
                    foreach (var line in fileLines)
                    {
                        if (id.ImplementationVersionString == line)
                        {
                            yield return id;
                        }
                    }
                }
            }
            
        }
    }
    public class Log4ShellIdentifier
    {
        public string ReleaseVersionString { get; set; }
        public string Version { get; set; }
        public List<string> CVEs { get; set; }
        public string JdniLookupHash { get; set; }
        public string JdniManagerHash { get; set; }
        public string SocketNodeHash { get; set; }
        public string ImplementationVersionString { get; set; }
    }
}
