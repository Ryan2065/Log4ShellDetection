Function Get-Log4ShellIdentifiers{
    Param(
        [string[]]$CVEsToDetect
    )
    if($null -eq $Script:Log4ShellIds -or ( $null -ne $CVEsToDetect )){
    #output from Search-DownloadedJars.ps1
        $Script:Log4ShellIds = @'
        [
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "7f0add9055958365137a8cc7a90969a43c44b20280323bdac718c1ff3795beb8",
                "MavenVersion":  "2.3.2",
                "Hash-MANIFEST.MF":  "a4d9f66acd3c53fa67f086f968da4efc71b1cdc5439e3aa892557e8986a73aae",
                "Hash-JndiManager.class":  "89535e03625d7ed5074d12eab85a9b27a643fcaf9ed62b152371d209ee90ce80"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
                "MavenVersion":  "2.12.4",
                "Hash-MANIFEST.MF":  "776c2565dbd52f1ee7bca5e815ffc8ced000277b862a6444f2e985374f9a4bf3",
                "Hash-JndiManager.class":  "a954ff8c69d43a40dac017ec01ecc56f6c39d9122cb3c388abbe89b975a6fe95"
            },
            {
                "CVE":  "CVE-2021-4104",
                "Hash-JndiLookup.class":  "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
                "MavenVersion":  "2.17.1",
                "Hash-MANIFEST.MF":  "d6f98fdaa54d72e5ca3561189ad2f08789371ac3dbd745670eee0ec8e89c1c9d",
                "Hash-JndiManager.class":  "3588a6aaf84fa79215a1cc5d12dee69413b8772656c73bdf26ef35df713b1091"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0ad99a95ff637fc966fc4ce5fe1f9e78d3b24b113282f9990b95a6fde3383d9c",
                "MavenVersion":  "2.3.1",
                "Hash-MANIFEST.MF":  "b0a89eaba3af03320fcbf93fbf4a3fe4b70a9912a70d1c6050e3a4f499871b3f",
                "Hash-JndiManager.class":  "6ce4436eca5edc852d375cbc831cd652b80fc16f6238cd2b22bd115b3735460e"
            },
            {
                "CVE":  "CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "edb797a8633f629b7c2187ccafd259a16a0b7b4cce4d42e646f8472358b8962a",
                "MavenVersion":  "2.12.3",
                "Hash-MANIFEST.MF":  "91e64c45c98ad57d0f808de5c558f23dc17eed7353ea0a66ce6e786e5638c3fb",
                "Hash-JndiManager.class":  "f04dd01860bb32750a47fc3f6b29a41b4dd04736fadf0fd63c4f1909d845afd2"
            },
            {
                "CVE":  "CVE-2021-44832,CVE-2021-44832,CVE-2021-4104",
                "Hash-JndiLookup.class":  "ddad241274b834182525eeddc35c3198247507bd2df59645b58b94cd18fada7c",
                "MavenVersion":  "2.17.0",
                "Hash-MANIFEST.MF":  "93fb82ff2d2c4e6b8efbb1d15f30002b898cdbaec668d789f77c7cf1b91f1c70",
                "Hash-JndiManager.class":  "9c2a6ea36c79fa23da59cc0f6c52c07ce54ca145ddd654790a3116d2b24de51b"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "febbc7867784d0f06934fec59df55ee45f6b24c55b17fff71cc4fca80bf22ebb",
                "MavenVersion":  "2.12.2",
                "Hash-MANIFEST.MF":  "b2d9f91759d1f7528f6461d1911c0019bc34e7fa3f9bc6a40c92e6cb4b48fef4",
                "Hash-JndiManager.class":  "b1960d63a3946f9e16e1920624f37c152b58b98932ed04df99ed5d9486732afb"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-44832,CVE-2021-4104",
                "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                "MavenVersion":  "2.16.0",
                "Hash-MANIFEST.MF":  "fd871789b0df7c0cb6371a78ea4502526b5b64a00dad59f6ad40093106755edd",
                "Hash-JndiManager.class":  "5210e6aae7dd8a61cd16c56937c5f2ed43941487830f46e99d0d3f45bfa6f953"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-4104",
                "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                "MavenVersion":  "2.15.0",
                "Hash-MANIFEST.MF":  "c9b27e591f414c2ab9926bf1183c6cdb9f2f5067aab45095ce9bb83ac30ba6b9",
                "Hash-JndiManager.class":  "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                "MavenVersion":  "2.14.1",
                "Hash-MANIFEST.MF":  "82d9fd84f295836d1be3fdb51100a6f0eda5546ef7ab7f23c2d15146a40acc23",
                "Hash-JndiManager.class":  "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f",
                "MavenVersion":  "2.14.0",
                "Hash-MANIFEST.MF":  "5ce64748e99fe84ff00334b862aed77bb7035887a978c69a6b1824cc14ae6b4e",
                "Hash-JndiManager.class":  "77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                "MavenVersion":  "2.13.3",
                "Hash-MANIFEST.MF":  "013d78bef8ae099878510c0ea59a75fc567661f324647b758a0f8086b8b19846",
                "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                "MavenVersion":  "2.13.2",
                "Hash-MANIFEST.MF":  "d3c8c0593c4b538f613acc5e90649ba3ae0ff74ba2a8bff45f824ce2f62e6c11",
                "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                "MavenVersion":  "2.13.1",
                "Hash-MANIFEST.MF":  "8b9687c805f770c87d0e6a66a2b9b0014a41619a8bfd0826e43ae31288b1327a",
                "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f",
                "MavenVersion":  "2.13.0",
                "Hash-MANIFEST.MF":  "74861ce0e2bb0c938f35ca111424627c2bbbf914730c0a7110ae2df2bfc38d27",
                "Hash-JndiManager.class":  "c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
                "MavenVersion":  "2.12.1",
                "Hash-MANIFEST.MF":  "6afde93626242594ce53bd50dfc9cfce9b0b33a833bf8c6b5b587d48f2906742",
                "Hash-JndiManager.class":  "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279",
                "MavenVersion":  "2.12.0",
                "Hash-MANIFEST.MF":  "3828d288b1559aa146bbec7688070dd52d0e0c99c087ddee837060ef8ada43fe",
                "Hash-JndiManager.class":  "1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.11.2",
                "Hash-MANIFEST.MF":  "7ceaa94e520ab015fdbdeb53467cdaf1cff650b782113f0db5ebf05f4a572761",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.11.1",
                "Hash-MANIFEST.MF":  "ec05ab68b4d11cf0c7ccf1fce71afc90354c1487870db6814605b96c108cc505",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.11.0",
                "Hash-MANIFEST.MF":  "5d52f59092aad09b01fa5aaab9372b5aef3470256f16db4349e8e6729624bdfc",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.10.0",
                "Hash-MANIFEST.MF":  "9d3875ccb3f1b1df813403fa4703f1d4090d46a725c9eb1ca562a615ff931922",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.9.1",
                "Hash-MANIFEST.MF":  "e49b7d36d987a54c87f15cff0f607001668bb2597f59fb6059aa4d5c37e80c11",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e",
                "MavenVersion":  "2.9.0",
                "Hash-MANIFEST.MF":  "f26b5b96588759cffab977baf83ddf497920a6ae3a7f5bf6fcc9d49e7852eb18",
                "Hash-JndiManager.class":  "293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15",
                "MavenVersion":  "2.8.2",
                "Hash-MANIFEST.MF":  "989f2e565313cf5b5751c038c10e3ecae00a3826d7bda82aef2dbe0623cdee8a",
                "Hash-JndiManager.class":  "764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
                "MavenVersion":  "2.8.1",
                "Hash-MANIFEST.MF":  "60b0e45128a4290198fa53d2e314497c55cdefd52ad81f71b5e838f0374d0537",
                "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442",
                "MavenVersion":  "2.8",
                "Hash-MANIFEST.MF":  "a1cc450ae4650a7e4ced8e56bc57dee958ca4c99c053b647af61b1aa1b116be5",
                "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae",
                "MavenVersion":  "2.7",
                "Hash-MANIFEST.MF":  "a129123fdc8fd756ec315476142e71fc0e2bb070d0ff0b9757e90f8f6b76ac81",
                "Hash-JndiManager.class":  "1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                "MavenVersion":  "2.6.2",
                "Hash-MANIFEST.MF":  "8153d2d69a926350a967b94aefb315291173ed4416b799484b4212e64c33a9bc",
                "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                "MavenVersion":  "2.6.1",
                "Hash-MANIFEST.MF":  "d2a53b80fa6bf70b92fe456ac96dfbadb94a37dd4bfd4ff7e91d5a9c5b8f0fc2",
                "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45",
                "MavenVersion":  "2.6",
                "Hash-MANIFEST.MF":  "3bed4acfd98894d5494b342d047d5b20ae3f1620c2a0b2ac08884e8bcde1b061",
                "Hash-JndiManager.class":  "6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                "MavenVersion":  "2.5",
                "Hash-MANIFEST.MF":  "8169106f2ccee6c7e440103487e84e6b15a675bfad3bd674c634e6270bb8a576",
                "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                "MavenVersion":  "2.4.1",
                "Hash-MANIFEST.MF":  "73f069efed531516ec97718d169f2bf3a1fc5748767430d35c24d412c5d7afb8",
                "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7",
                "MavenVersion":  "2.4",
                "Hash-MANIFEST.MF":  "b16c49735a102e95fecae6f6d11f8f556accbda0ee2db3a7d1a2e0343cd0b763",
                "Hash-JndiManager.class":  "3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                "MavenVersion":  "2.3",
                "Hash-MANIFEST.MF":  "b0b6a5d2cc263319fd4542e389cafd5d2b4027eaf92b3c4eaf8f7dd431a8c689",
                "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                "MavenVersion":  "2.2",
                "Hash-MANIFEST.MF":  "e8011f8091db9e6adb790605d0952635feb70a645f8648d80856417cb376dd6a",
                "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307",
                "MavenVersion":  "2.1",
                "Hash-MANIFEST.MF":  "e640dcbe5ef72e238667c08803c223aabab55f1ed74b244c8db5b92d7b91dfd3",
                "Hash-JndiManager.class":  "ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c",
                "MavenVersion":  "2.0.2",
                "Hash-MANIFEST.MF":  "cff76ac7f0e32cff32eb5f1aefdbef6669a1af4df148a3137fd7192d56c29b35"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e",
                "MavenVersion":  "2.0.1",
                "Hash-MANIFEST.MF":  "701390a3e20ee0997407e332bfee90803d84c3d9950f6547a40e3a093ec846cb"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29",
                "MavenVersion":  "2.0",
                "Hash-MANIFEST.MF":  "204b1636b4794953fa04a3c221f744ea92a3353c49e99b83e250779845c8b68a"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2",
                "MavenVersion":  "2.0-rc2",
                "Hash-MANIFEST.MF":  "f7d65673a792b8bd490008bdfb5847bdd6c653d7a7d48407448b81c766f18e62"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
                "MavenVersion":  "2.0-rc1",
                "Hash-MANIFEST.MF":  "e55937b091922d5017d1bef672c5983a57bc90a59b9478bb8dd5d15e8796a32b"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-45046,CVE-2021-44832,CVE-2021-44832,CVE-2021-44228,CVE-2021-4104",
                "Hash-JndiLookup.class":  "39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8",
                "MavenVersion":  "2.0-beta9",
                "Hash-MANIFEST.MF":  "c7faf19ed3b250012cf874fa4d327557a7e168e9dc0245114bccdd3e0bd9e47a"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta8",
                "Hash-MANIFEST.MF":  "d70c4a4cd66229b4a6755d289f03b97bca9a98bbf628b56678870760f0f9b8da"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta7",
                "Hash-MANIFEST.MF":  "fc04173e7a6c361466f239f4279d2be19806b95e886d8d989334b646552fa4dd"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta6",
                "Hash-MANIFEST.MF":  "09ff8009d22002f074141e98e3f50b59f9ca8f042bf9bad633987094ce58fe98"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta5",
                "Hash-MANIFEST.MF":  "a24efc74d1c055749bca0315b69f95932c328cfa7df326b187f7a71c900816db"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta4",
                "Hash-MANIFEST.MF":  "b8703a07108cf877b76686b743bb4b45637465fb601a35f32d7b0926af57f12d"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta3",
                "Hash-MANIFEST.MF":  "3af6bac5ad5904a1067c1a8ee8db45cda8d5bc5811f93e8166920f9d54fed2c9"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta2",
                "Hash-MANIFEST.MF":  "8a311b019c8eca2ddc565a3035fe6f2f39ee45705c2e8bc44a7e7c2b5fac563d"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-44832,CVE-2021-4104",
                "MavenVersion":  "2.0-beta1",
                "Hash-MANIFEST.MF":  "7beaacc5bb8077c973733aac9fb47b6d62e552b76c9057966b19362ebef3c60d"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-4104",
                "MavenVersion":  "2.0-alpha2",
                "Hash-MANIFEST.MF":  "e138712ef7f724c0e33b2706d5565f0d666faa3df15c6c1995e28782f87c4ec5"
            },
            {
                "CVE":  "CVE-2021-45105,CVE-2021-4104",
                "MavenVersion":  "2.0-alpha1",
                "Hash-MANIFEST.MF":  "f4471540465a1d22f1ffb52c44ffce215d50ace2c26cb5a7332e1d499700f478"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.17",
                "Hash-MANIFEST.MF":  "ab112ec5c8d959a815101acc78dddcae58955ce0d3d8304715f595570b9188a6",
                "Hash-SocketNode.class":  "8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.16",
                "Hash-MANIFEST.MF":  "721b8ab2b05a0084c30f017bee714fb33b97dcb6b8ed4bec7b93fd5fb7fa492a",
                "Hash-SocketNode.class":  "688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.15",
                "Hash-MANIFEST.MF":  "9296b90fecdd5611afa85208b6cbab2d96c4d812d9a6f468367a79e50e030658",
                "Hash-SocketNode.class":  "7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.14",
                "Hash-MANIFEST.MF":  "ad4e787d8cc3f13c87ffa54076ad2f9b839532394e38a197ef1cefe609575d15",
                "Hash-SocketNode.class":  "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.13",
                "Hash-MANIFEST.MF":  "1882eeaad6366a652461d2e1a08a47e6ae1db44065d33ab79cb8418bc567b032",
                "Hash-SocketNode.class":  "fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.9",
                "Hash-MANIFEST.MF":  "8db13dca2f62cfc55f50b0841dcc2efb1a491d423b234b57b2bd611228191d9a",
                "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.12",
                "Hash-MANIFEST.MF":  "c7dc7a3dbeb69fcb2dd44a2c599da459e1298565ebca35ceda8501a30fd6f15b",
                "Hash-SocketNode.class":  "f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.11",
                "Hash-MANIFEST.MF":  "65e930e4c01bf80296d17c016efef788347367599e32d9037abeec401b7a5fd2",
                "Hash-SocketNode.class":  "d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.8",
                "Hash-MANIFEST.MF":  "9a62e164e4fa72cf7eeace6940d5ce583055450e3294660ac5ba03e9f42a96c2",
                "Hash-SocketNode.class":  "bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.7",
                "Hash-MANIFEST.MF":  "1f235eb79cddc11c384b7eebf7f917b129197d5ced8288334442e0b183828fb2",
                "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.6",
                "Hash-MANIFEST.MF":  "00dc440d84da3f78a9398ea7270ba81d988c9c40541e5265a46be002a82ff9b5",
                "Hash-SocketNode.class":  "3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.5",
                "Hash-MANIFEST.MF":  "8a233ff1d8342e2be8918f7c24c5f35e18d2534a31939fb806bacead952b4fdf",
                "Hash-SocketNode.class":  "ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a"
            },
            {
                "CVE":  "CVE-2021-4104",
                "MavenVersion":  "1.2.4",
                "Hash-MANIFEST.MF":  "9158047be7fa969fd32f8483d74ea770ca03f308f11b8fc2e4645a6c262b0931",
                "Hash-SocketNode.class":  "6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d"
            }
        ]
        
'@ | ConvertFrom-JSON
        if($null -ne $CVEsToDetect){
            $FixedLog4ShellIdList = @()
            foreach($instance in $Script:Log4ShellIds){
                $instanceCVEList = $instance.CVE.Split(",")
                $NewCVEList = @()
                foreach($i in $instanceCVEList){
                    if($CVEsToDetect -contains $i){
                        $NewCVEList += $i
                    }
                }
                if($NewCVEList.Count -gt 0){
                    $instance.CVE = $NewCVEList -join ","
                    $FixedLog4ShellIdList += $instance
                }
            }
            $Script:Log4ShellIds = $FixedLog4ShellIdList
        }
    }
    return $Script:Log4ShellIds
}