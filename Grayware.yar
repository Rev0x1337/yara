rule Greyware
{
    strings:
        
        $string1_whoami_greyware_tool_keyword = " -exec bypass -nop -c whoami" nocase ascii wide
        $string2_whoami_greyware_tool_keyword = "whoami /all" nocase ascii wide
        $string3_whoami_greyware_tool_keyword = "whoami /domain" nocase ascii wide
        $string4_whoami_greyware_tool_keyword = "whoami /groups" nocase ascii wide
        $string5_whoami_greyware_tool_keyword = "whoami /priv" nocase ascii wide
        $string6_whoami_greyware_tool_keyword = "whoami" nocase ascii wide
        $string7_whoami_greyware_tool_keyword = /whoami\.exe.{0,100}\s\/groups/ nocase ascii wide
       
        $string1_ScreenConnect_greyware_tool_keyword = /\:8040\/SetupWizard\.aspx/ nocase ascii wide
        $string2_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect\sClient\s\(/ nocase ascii wide
        $string3_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Services\\ScreenConnect\s/ nocase ascii wide
        $string4_ScreenConnect_greyware_tool_keyword = /\\Documents\\ConnectWiseControl\\Files/ nocase ascii wide
        $string5_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.cl/ nocase ascii wide
        $string6_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.wi/ nocase ascii wide
        $string7_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\sClient\s\(/ nocase ascii wide
        $string8_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
        $string9_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
        $string10_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        $string11_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Core\.dll/ nocase ascii wide
        $string12_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.InstallerActions\.dll/ nocase ascii wide
        $string13_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Windows\.dll/ nocase ascii wide
        $string14_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        $string15_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        $string16_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\\Bin\\/ nocase ascii wide
        $string17_ScreenConnect_greyware_tool_keyword = /\\TEMP\\ScreenConnect\\.{0,100}\.ps1/ nocase ascii wide
        $string18_ScreenConnect_greyware_tool_keyword = /\\Temp\\ScreenConnect\\.{0,100}\\setup\.msi/ nocase ascii wide
        $string19_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,100}\.cmd/ nocase ascii wide
        $string20_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,100}\.ps1/ nocase ascii wide
        $string21_ScreenConnect_greyware_tool_keyword = "<Data>ScreenConnect Software</Data>" nocase ascii wide
        $string22_ScreenConnect_greyware_tool_keyword = "<Provider Name='ScreenConnect Security Manager'/>" nocase ascii wide
        $string23_ScreenConnect_greyware_tool_keyword = "<Provider Name='ScreenConnect Web Server'/>" nocase ascii wide
        $string24_ScreenConnect_greyware_tool_keyword = /cmd\.exe.{0,100}\\TEMP\\ScreenConnect\\.{0,100}\.cmd/ nocase ascii wide
        $string25_ScreenConnect_greyware_tool_keyword = /https\:\/\/.{0,100}\.screenconnect\.com\/Bin\/.{0,100}\.exe/ nocase ascii wide
        $string26_ScreenConnect_greyware_tool_keyword = /https\:\/\/.{0,100}\.screenconnect\.com\/Host/ nocase ascii wide
        $string27_ScreenConnect_greyware_tool_keyword = /https\:\/\/cloud\.screenconnect\.com\/\#\/trialtoinstance\?cookieValue\=/ nocase ascii wide
        $string28_ScreenConnect_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\ScreenConnect\sClient/ nocase ascii wide
        $string29_ScreenConnect_greyware_tool_keyword = /\-relay\.screenconnect\.com/ nocase ascii wide
        $string30_ScreenConnect_greyware_tool_keyword = "ScreenConnect Software" nocase ascii wide
        $string31_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.dll/ nocase ascii wide
        $string32_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.exe\.jar/ nocase ascii wide
        $string33_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.dll/ nocase ascii wide
        $string34_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.exe/ nocase ascii wide
        $string35_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        $string36_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.CLIENTSETUP\.EXE\-.{0,100}\.pf/ nocase ascii wide
        $string37_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientUninstall\.vbs/ nocase ascii wide
        $string38_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Core\.pdb/ nocase ascii wide
        $string39_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Server\.dll/ nocase ascii wide
        $string40_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Service\.exe/ nocase ascii wide
        $string41_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.SERVICE\.EXE\-.{0,100}\.pf/ nocase ascii wide
        $string42_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        $string43_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.WINDOWSCLIENT\..{0,100}\.pf/ nocase ascii wide
        $string44_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        $string45_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsInstaller\.dll/ nocase ascii wide
        $string46_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.msi/ nocase ascii wide
        $string47_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.tar\.gz/ nocase ascii wide
        $string48_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,100}_Release\.zip/ nocase ascii wide
        $string49_ScreenConnect_greyware_tool_keyword = /ScreenConnectClientNetworkDeployer\.exe/ nocase ascii wide
        $string50_ScreenConnect_greyware_tool_keyword = /server.{0,100}\-relay\.screenconnect\.com/ nocase ascii wide
        $string51_ScreenConnect_greyware_tool_keyword = /\-web\.screenconnect\.com/ nocase ascii wide
       
        $string1_Quasar_greyware_tool_keyword = " CN=Quasar Server CA" nocase ascii wide
        $string2_Quasar_greyware_tool_keyword = /\/Quasar\.git/ nocase ascii wide
        $string3_Quasar_greyware_tool_keyword = /\/Quasar\.v.{0,100}\.zip/ nocase ascii wide
        $string4_Quasar_greyware_tool_keyword = "/Quasar/releases" nocase ascii wide
        $string5_Quasar_greyware_tool_keyword = /\\appdata\\roaming\\.{0,100}\'DestPort\'\>4782\<\/Data\>/ nocase ascii wide
        $string6_Quasar_greyware_tool_keyword = /\\CurrentVersion\\Run\\Quasar\sClient\sStartup/ nocase ascii wide
        $string7_Quasar_greyware_tool_keyword = /\\Prefetch\\QUASAR\.EXE/ nocase ascii wide
        $string8_Quasar_greyware_tool_keyword = /\\Program\sFiles\\SubDir\\Client\.exe/ nocase ascii wide
        $string9_Quasar_greyware_tool_keyword = /\\Quasar\.Client\\/ nocase ascii wide
        $string10_Quasar_greyware_tool_keyword = /\\Quasar\.Common\\.{0,100}\.cs/ nocase ascii wide
        $string11_Quasar_greyware_tool_keyword = /\\quasar\.p12/ nocase ascii wide
        $string12_Quasar_greyware_tool_keyword = /\\Quasar\.v.{0,100}\.zip/ nocase ascii wide
        $string13_Quasar_greyware_tool_keyword = /\\Quasar\-master/ nocase ascii wide
        $string14_Quasar_greyware_tool_keyword = /\\Users\\mthcht\\AppData\\Roaming\\SubDir\\Client\.exe/ nocase ascii wide
        $string15_Quasar_greyware_tool_keyword = /\\Windows\\system32\\SubDir\\Client\.exe/ nocase ascii wide
        $string16_Quasar_greyware_tool_keyword = "14CA405B-8BAC-48AB-9FBA-8FB5DF88FD0D" nocase ascii wide
        $string17_Quasar_greyware_tool_keyword = "32A2A734-7429-47E6-A362-E344A19C0D85" nocase ascii wide
        $string18_Quasar_greyware_tool_keyword = "9F5CF56A-DDB2-4F40-AB99-2A1DC47588E1" nocase ascii wide
        $string19_Quasar_greyware_tool_keyword = /Backdoor\.Quasar/ nocase ascii wide
        $string20_Quasar_greyware_tool_keyword = "C7C363BA-E5B6-4E18-9224-39BC8DA73172" nocase ascii wide
        $string21_Quasar_greyware_tool_keyword = "CFCD0759E20F29C399C9D4210BE614E4E020BEE8" nocase ascii wide
        $string22_Quasar_greyware_tool_keyword = "localhost:4782" nocase ascii wide
        $string23_Quasar_greyware_tool_keyword = /namespace\sQuasar\.Client/ nocase ascii wide
        $string24_Quasar_greyware_tool_keyword = /namespace\sQuasar\.Server/ nocase ascii wide
        $string25_Quasar_greyware_tool_keyword = "ping -n 10 localhost > nul" nocase ascii wide
        $string26_Quasar_greyware_tool_keyword = "Quasar Client Startup" nocase ascii wide
        $string27_Quasar_greyware_tool_keyword = /Quasar\sv.{0,100}\\Client\-built\.exe/ nocase ascii wide
        $string28_Quasar_greyware_tool_keyword = /Quasar\.Client\./ nocase ascii wide
        $string29_Quasar_greyware_tool_keyword = /Quasar\.Common\.Tests\\/ nocase ascii wide
        $string30_Quasar_greyware_tool_keyword = /Quasar\.exe/ nocase ascii wide
        $string31_Quasar_greyware_tool_keyword = /Quasar\.Server/ nocase ascii wide
        $string32_Quasar_greyware_tool_keyword = /Quasar\.Server\\Program\.cs/ nocase ascii wide
        $string33_Quasar_greyware_tool_keyword = /Quasar\.sln/ nocase ascii wide
        $string34_Quasar_greyware_tool_keyword = /Quasar\.v1\.4\.1\.zip/ nocase ascii wide
        $string35_Quasar_greyware_tool_keyword = "quasar/Quasar" nocase ascii wide
        $string36_Quasar_greyware_tool_keyword = /Quasar\-master\.zip/ nocase ascii wide
        $string37_Quasar_greyware_tool_keyword = "QuasarRAT" nocase ascii wide
        $string38_Quasar_greyware_tool_keyword = "ylAo2kAlUS2kYkala!" nocase ascii wide
       
        $string1_telegram_greyware_tool_keyword = /\\AppData\\Roaming\\Telegram\sDesktop\\tdata/ nocase ascii wide
        $string2_telegram_greyware_tool_keyword = /api\.telegram\.org/ nocase ascii wide
        
        $string1_scp_greyware_tool_keyword = /scp\s.{0,100}\s.{0,100}\@.{0,100}\:/ nocase ascii wide
        $string2_scp_greyware_tool_keyword = /scp\s.{0,100}\@.{0,100}\:.{0,100}\s/ nocase ascii wide
        
        $string1_ngrok_greyware_tool_keyword = /\.ngrok\.me/ nocase ascii wide
        $string2_ngrok_greyware_tool_keyword = /\/ngrok\.exe/ nocase ascii wide
        $string3_ngrok_greyware_tool_keyword = /\/ngrok\.git/ nocase ascii wide
        $string4_ngrok_greyware_tool_keyword = /\/ngrok\.go/ nocase ascii wide
        $string5_ngrok_greyware_tool_keyword = /\/ngrok\.log/ nocase ascii wide
        $string6_ngrok_greyware_tool_keyword = /\/ngrokd\.go/ nocase ascii wide
        $string7_ngrok_greyware_tool_keyword = /\/ngrokroot\.crt/ nocase ascii wide
        $string8_ngrok_greyware_tool_keyword = /\\ngrok\.exe/ nocase ascii wide
        $string9_ngrok_greyware_tool_keyword = /\\ngrok\.go/ nocase ascii wide
        $string10_ngrok_greyware_tool_keyword = /\\ngrok\.log/ nocase ascii wide
        $string11_ngrok_greyware_tool_keyword = /\\ngrokd\.go/ nocase ascii wide
        $string12_ngrok_greyware_tool_keyword = "6abfc342f0a659066c8b42999510ccc3592b499569c2e7af37470a445a2e3560" nocase ascii wide
        $string13_ngrok_greyware_tool_keyword = "fe9dd722a085bce94fe2403f8d02e20becf0f0faa019d0789fadf35b66611a46" nocase ascii wide
        $string14_ngrok_greyware_tool_keyword = /http\:\/\/.{0,100}\.ngrok\.io/ nocase ascii wide
        $string15_ngrok_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/ nocase ascii wide
        $string16_ngrok_greyware_tool_keyword = /https\:\/\/.{0,100}\.ngrok\.io/ nocase ascii wide
        $string17_ngrok_greyware_tool_keyword = "inconshreveable/ngrok" nocase ascii wide
        $string18_ngrok_greyware_tool_keyword = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
        $string19_ngrok_greyware_tool_keyword = /Mozilla\/5\.0\s\(compatible\;\sngrok\)/ nocase ascii wide
        $string20_ngrok_greyware_tool_keyword = "ngrok tcp " nocase ascii wide
        $string21_ngrok_greyware_tool_keyword = /ngrok\,\sInc\./ nocase ascii wide
        $string22_ngrok_greyware_tool_keyword = /ngrokd\.ngrok\.com/ nocase ascii wide
        $string23_ngrok_greyware_tool_keyword = /tcp\:\/\/0\.tcp\.ngrok\.io\:/ nocase ascii wide
        $string24_ngrok_greyware_tool_keyword = /tunnel\.ap\.ngrok\.com/ nocase ascii wide
        $string25_ngrok_greyware_tool_keyword = /tunnel\.au\.ngrok\.com/ nocase ascii wide
        $string26_ngrok_greyware_tool_keyword = /tunnel\.eu\.ngrok\.com/ nocase ascii wide
        $string27_ngrok_greyware_tool_keyword = /tunnel\.in\.ngrok\.com/ nocase ascii wide
        $string28_ngrok_greyware_tool_keyword = /tunnel\.jp\.ngrok\.com/ nocase ascii wide
        $string29_ngrok_greyware_tool_keyword = /tunnel\.sa\.ngrok\.com/ nocase ascii wide
        $string30_ngrok_greyware_tool_keyword = /tunnel\.us\.ngrok\.com/ nocase ascii wide
        
        $string1_rdpwrap_greyware_tool_keyword = /\sRDPWInst\.exe/ nocase ascii wide
        $string2_rdpwrap_greyware_tool_keyword = /\srdpwrap\.dll/ nocase ascii wide
        $string3_rdpwrap_greyware_tool_keyword = "\"%~dp0RDPWInst\" -i -o" nocase ascii wide
        $string4_rdpwrap_greyware_tool_keyword = /\%\~dp0RDPWInst\.exe/ nocase ascii wide
        $string5_rdpwrap_greyware_tool_keyword = /\/RDPWInst\.exe/ nocase ascii wide
        $string6_rdpwrap_greyware_tool_keyword = /\/RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
        $string7_rdpwrap_greyware_tool_keyword = /\/rdpwrap\.dll/ nocase ascii wide
        $string8_rdpwrap_greyware_tool_keyword = /\/rdpwrap\.git/ nocase ascii wide
        $string9_rdpwrap_greyware_tool_keyword = /\/RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
        $string10_rdpwrap_greyware_tool_keyword = /\/res\/rdpwrap\.ini/ nocase ascii wide
        $string11_rdpwrap_greyware_tool_keyword = /\\bin\\RDPConf\.exe/ nocase ascii wide
        $string12_rdpwrap_greyware_tool_keyword = /\\RDP\sWrapper\\/ nocase ascii wide
        $string13_rdpwrap_greyware_tool_keyword = /\\RDPCheck\.exe/ nocase ascii wide
        $string14_rdpwrap_greyware_tool_keyword = /\\RDPWInst\.exe/ nocase ascii wide
        $string15_rdpwrap_greyware_tool_keyword = /\\RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
        $string16_rdpwrap_greyware_tool_keyword = /\\RDPWrap\.cpp/ nocase ascii wide
        $string17_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.dll/ nocase ascii wide
        $string18_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.ini/ nocase ascii wide
        $string19_rdpwrap_greyware_tool_keyword = /\\RDPWrap\.sln/ nocase ascii wide
        $string20_rdpwrap_greyware_tool_keyword = /\\rdpwrap\.txt/ nocase ascii wide
        $string21_rdpwrap_greyware_tool_keyword = /\\rdpwrap\-master/ nocase ascii wide
        $string22_rdpwrap_greyware_tool_keyword = /\\RDPWrapSetup/ nocase ascii wide
        $string23_rdpwrap_greyware_tool_keyword = /\\RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
        $string24_rdpwrap_greyware_tool_keyword = "1232372059db3ecf28cc2609a36b7f20cef2dfe0618770e3ebaa9488bc7fc2de" nocase ascii wide
        $string25_rdpwrap_greyware_tool_keyword = "29E4E73B-EBA6-495B-A76C-FBB462196C64" nocase ascii wide
        $string26_rdpwrap_greyware_tool_keyword = "35a9481ddbed5177431a9ea4bd09468fe987797d7b1231d64942d17eb54ec269" nocase ascii wide
        $string27_rdpwrap_greyware_tool_keyword = "3699b102bf5ad1120ef560ae3036f27c74f6161b62b31fda8087bd7ae1496ee1" nocase ascii wide
        $string28_rdpwrap_greyware_tool_keyword = "9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de" nocase ascii wide
        $string29_rdpwrap_greyware_tool_keyword = "aaf7e238a5c0bb2a7956e2fdca9b534f227f7b737641962fb0ed965390ace4c6" nocase ascii wide
        $string30_rdpwrap_greyware_tool_keyword = "f9a82873a1e55bb1b5b8b8781b06799ff665464cff8ce77e07474c089123b643" nocase ascii wide
        $string31_rdpwrap_greyware_tool_keyword = "fed08bd733b8e60b5805007bd01a7bf0d0b1993059bbe319d1179facc6b73361" nocase ascii wide
        $string32_rdpwrap_greyware_tool_keyword = "Initializing RDP Wrapper" nocase ascii wide
        $string33_rdpwrap_greyware_tool_keyword = /\'RDP\sWrapper\sLibrary\sInstaller\sv1\.0\'/ nocase ascii wide
        $string34_rdpwrap_greyware_tool_keyword = /RDP\sWrapper\\RDPConf/ nocase ascii wide
        $string35_rdpwrap_greyware_tool_keyword = "RDPWInst -w" nocase ascii wide
        $string36_rdpwrap_greyware_tool_keyword = /rdpwrap\\.{0,100}\\RDPWInst\./ nocase ascii wide
        $string37_rdpwrap_greyware_tool_keyword = "stascorp/rdpwrap" nocase ascii wide
        
        $string1_FileZilla_greyware_tool_keyword = /\/FileZilla_.{0,100}_sponsored\-setup\.exe/ nocase ascii wide
        $string2_FileZilla_greyware_tool_keyword = /\/FileZilla_Server_.{0,100}\.deb/ nocase ascii wide
        $string3_FileZilla_greyware_tool_keyword = /\\FileZilla_.{0,100}_sponsored\-setup\.exe/ nocase ascii wide
        $string4_FileZilla_greyware_tool_keyword = /\\FILEZILLA_.{0,100}_WIN64_SPONSO\-.{0,100}\.pf/ nocase ascii wide
        $string5_FileZilla_greyware_tool_keyword = /\\FileZilla_.{0,100}\-setup\.exe/ nocase ascii wide
        $string6_FileZilla_greyware_tool_keyword = /\\FileZilla_Server_/ nocase ascii wide
        $string7_FileZilla_greyware_tool_keyword = /\\Program\sFiles\\FileZilla\sFTP\sClient\\/ nocase ascii wide
        $string8_FileZilla_greyware_tool_keyword = /\\Program\sFiles\\FileZilla\sServer/ nocase ascii wide
        $string9_FileZilla_greyware_tool_keyword = /\\Software\\WOW6432Node\\FileZilla\sClient/ nocase ascii wide
        $string10_FileZilla_greyware_tool_keyword = ">FileZilla FTP Client<" nocase ascii wide
        $string11_FileZilla_greyware_tool_keyword = ">FileZilla Server<" nocase ascii wide
        $string12_FileZilla_greyware_tool_keyword = /download\.filezilla\-project\.org/ nocase ascii wide
        $string13_FileZilla_greyware_tool_keyword = /Software\\FileZilla/ nocase ascii wide
        $string14_FileZilla_greyware_tool_keyword = "Win32/FileZilla_BundleInstaller" nocase ascii wide
        
        $string1_processhacker_greyware_tool_keyword = /\/processhacker\-.{0,100}\-bin\.zip/ nocase ascii wide
        $string2_processhacker_greyware_tool_keyword = "/processhacker/files/latest/download" nocase ascii wide
        $string3_processhacker_greyware_tool_keyword = /\\Process\sHacker\s2\\/ nocase ascii wide
        $string4_processhacker_greyware_tool_keyword = /processhacker\-.{0,100}\-sdk\.zip/ nocase ascii wide
        $string5_processhacker_greyware_tool_keyword = /processhacker\-.{0,100}\-setup\.exe/ nocase ascii wide
        $string6_processhacker_greyware_tool_keyword = /processhacker\-.{0,100}\-src\.zip/ nocase ascii wide
        $string7_processhacker_greyware_tool_keyword = /ProcessHacker\.exe/ nocase ascii wide
        $string8_processhacker_greyware_tool_keyword = /ProcessHacker\.sln/ nocase ascii wide
        
        $string22_bash_greyware_tool_keyword = /rm\s\.bash_history/ nocase ascii wide
        $string23_bash_greyware_tool_keyword = /rm\s\/home\/.{0,100}\/\.bash_history/ nocase ascii wide
        $string24_bash_greyware_tool_keyword = /rm\s\/root\/\.bash_history/ nocase ascii wide
        $string25_bash_greyware_tool_keyword = /set\shistory\s\+o/ nocase ascii wide
        $string26_bash_greyware_tool_keyword = /sh\s\>\/dev\/tcp\/.{0,100}\s\<\&1\s2\>\&1/ nocase ascii wide
        $string27_bash_greyware_tool_keyword = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,100}\/.{0,100}\s0\>\&1/ nocase ascii wide
        $string28_bash_greyware_tool_keyword = /truncate\s\-s0\s.{0,100}bash_history\'/ nocase ascii wide
        $string29_bash_greyware_tool_keyword = "unset HISTFILE" nocase ascii wide
        
        $string1__base64_greyware_tool_keyword = /\|\sbase64\s\-d\s/ nocase ascii wide
        $string2__base64_greyware_tool_keyword = "base64 -d /tmp/" nocase ascii wide
        
        $string1_netstat_greyware_tool_keyword = "netsat -naop" nocase ascii wide
        $string2_netstat_greyware_tool_keyword = "netstat -ano" nocase ascii wide
        $string3_netstat_greyware_tool_keyword = "netstat -ant" nocase ascii wide
        $string4_netstat_greyware_tool_keyword = /NETSTAT\.EXE.{0,100}\s\-ano/ nocase ascii wide
        
        $string1_shell_greyware_tool_keyword = /\/bin\/sh\s\|\snc/ nocase ascii wide
        $string2_shell_greyware_tool_keyword = "/bin/sh -i <&3 >&3 2>&3" nocase ascii wide
        $string3_shell_greyware_tool_keyword = /rm\s\-f\sbackpipe.{0,100}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
        $string4_shell_greyware_tool_keyword = "sc config WinDefend start= disabled" nocase ascii wide
        $string5_shell_greyware_tool_keyword = "schkconfig off cbdaemon" nocase ascii wide
        $string6_shell_greyware_tool_keyword = "service cbdaemon stop" nocase ascii wide
        $string7_shell_greyware_tool_keyword = /socket\(S.{0,100}PF_INET.{0,100}SOCK_STREAM.{0,100}getprotobyname\(.{0,100}tcp.{0,100}\)\).{0,100}if\(connect\(S.{0,100}sockaddr_in\(\$p.{0,100}inet_aton\(\$i\)\)\)\)/ nocase ascii wide
        $string8_shell_greyware_tool_keyword = /STDIN\-\>fdopen\(\$c.{0,100}r\).{0,100}\$\~\-\>fdopen\(\$c.{0,100}w\).{0,100}system\$_\swhile\<\>/ nocase ascii wide
        $string9_shell_greyware_tool_keyword = /uname\s\-a.{0,100}\sw.{0,100}\sid.{0,100}\s\/bin\/bash\s\-i/ nocase ascii wide
        $string10_shell_greyware_tool_keyword = "setenforce 0" nocase ascii wide
        
        $string1_bcdedit_greyware_tool_keyword = /bcdedit\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
        $string2_bcdedit_greyware_tool_keyword = /bcdedit\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
        $string3_bcdedit_greyware_tool_keyword = /bcdedit.{0,100}\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
        $string4_bcdedit_greyware_tool_keyword = /bcdedit.{0,100}\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
        
        $string1_vssadmin_greyware_tool_keyword = /\.exe\sdelete\sshadows/ nocase ascii wide
        $string2_vssadmin_greyware_tool_keyword = "vssadmin create shadow /for=C:" nocase ascii wide
        $string3_vssadmin_greyware_tool_keyword = /vssadmin\screate\sshadow\s\/for\=C\:.{0,100}\s\\Temp\\.{0,100}\.tmp/ nocase ascii wide
        $string4_vssadmin_greyware_tool_keyword = "vssadmin delete shadows" nocase ascii wide
        $string5_vssadmin_greyware_tool_keyword = "vssadmin list shadows" nocase ascii wide
        $string6_vssadmin_greyware_tool_keyword = /vssadmin.{0,100}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide
        $string7_vssadmin_greyware_tool_keyword = /vssadmin\.exe\sCreate\sShadow\s\/for\=/ nocase ascii wide
        
        $string1_wbadmin_greyware_tool_keyword = "wbadmin delete backup" nocase ascii wide
        $string2_wbadmin_greyware_tool_keyword = "wbadmin delete catalog -quiet" nocase ascii wide
        $string3_wbadmin_greyware_tool_keyword = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" nocase ascii wide
        $string4_wbadmin_greyware_tool_keyword = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase ascii wide
        
        $string1_Cmdkey_greyware_tool_keyword = "Cmdkey /list" nocase ascii wide
        
        $string1_psexec_greyware_tool_keyword = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
        $string2_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
        $string3_psexec_greyware_tool_keyword = /\\PsExec\.exe/ nocase ascii wide
        $string4_psexec_greyware_tool_keyword = /\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted/ nocase ascii wide
        $string5_psexec_greyware_tool_keyword = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
        $string6_psexec_greyware_tool_keyword = /\\Windows\\PSEXEC\-.{0,100}\.key/ nocase ascii wide
        $string7_psexec_greyware_tool_keyword = /PSEXEC\-.{0,100}\.key/ nocase ascii wide
        $string8_psexec_greyware_tool_keyword = /PsExec\[1\]\.exe/ nocase ascii wide
        $string9_psexec_greyware_tool_keyword = /PsExec64\.exe/ nocase ascii wide
        $string10_psexec_greyware_tool_keyword = "PSEXECSVC" nocase ascii wide
        $string11_psexec_greyware_tool_keyword = /PSEXECSVC\.EXE\-.{0,100}\.pf/ nocase ascii wide
        
        $string1_openssh_portable_greyware_tool_keyword = /\\\\pipe\\\\openssh\-ssh\-agent/ nocase ascii wide
        $string2_openssh_portable_greyware_tool_keyword = /\\OpenSSHTestTasks\\/ nocase ascii wide
        $string3_openssh_portable_greyware_tool_keyword = /\\pipe\\openssh\-ssh\-agent/ nocase ascii wide
        $string4_openssh_portable_greyware_tool_keyword = /\\Software\\OpenSSH\\DefaultShell/ nocase ascii wide
        $string5_openssh_portable_greyware_tool_keyword = /install\-sshd\.ps1/ nocase ascii wide
        $string6_openssh_portable_greyware_tool_keyword = "net start ssh-agent" nocase ascii wide
        $string7_openssh_portable_greyware_tool_keyword = "New-Service -Name sshd" nocase ascii wide
        
        $string1_systeminfo_greyware_tool_keyword = "cmd /c systeminfo" nocase ascii wide
        $string2_systeminfo_greyware_tool_keyword = /cmd\.exe\s\/c\ssysteminfo/ nocase ascii wide
        
        $string1_tightvnc_greyware_tool_keyword = " -service TightVNC Server" nocase ascii wide
        $string2_tightvnc_greyware_tool_keyword = /\.\\TightVNC1/ nocase ascii wide
        $string3_tightvnc_greyware_tool_keyword = /\.\\TightVNC2/ nocase ascii wide
        $string4_tightvnc_greyware_tool_keyword = /\.\\TightVNC3/ nocase ascii wide
        $string5_tightvnc_greyware_tool_keyword = /\/tightvnc\-.{0,100}\.msi/ nocase ascii wide
        $string6_tightvnc_greyware_tool_keyword = /\\mlnhcpkomdeavomsjalt/ nocase ascii wide
        $string7_tightvnc_greyware_tool_keyword = /\\Programs\\TightVNC/ nocase ascii wide
        $string8_tightvnc_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\TightVNC\\/ nocase ascii wide
        $string9_tightvnc_greyware_tool_keyword = /\\TightVNC\sServer/ nocase ascii wide
        $string10_tightvnc_greyware_tool_keyword = /\\tightvnc\-/ nocase ascii wide
        $string11_tightvnc_greyware_tool_keyword = /\\TightVNC_Service_Control/ nocase ascii wide
        $string12_tightvnc_greyware_tool_keyword = /\\TVN_log_pipe_public_name/ nocase ascii wide
        $string13_tightvnc_greyware_tool_keyword = ">TightVNC Viewer<" nocase ascii wide
        $string14_tightvnc_greyware_tool_keyword = /00\:\\\.vnc\\/ nocase ascii wide
        $string15_tightvnc_greyware_tool_keyword = /GlavSoft\sLLC\./ nocase ascii wide
        $string16_tightvnc_greyware_tool_keyword = /HKCR\\\.vnc/ nocase ascii wide
        $string17_tightvnc_greyware_tool_keyword = /program\sfiles\s\(x86\)\\tightvnc\\/ nocase ascii wide
        $string18_tightvnc_greyware_tool_keyword = /ProgramData\\TightVNC/ nocase ascii wide
        $string19_tightvnc_greyware_tool_keyword = "TightVNC Service" nocase ascii wide
        $string20_tightvnc_greyware_tool_keyword = /TightVNC\sWeb\sSite\.url/ nocase ascii wide
        $string21_tightvnc_greyware_tool_keyword = "tvnserver" nocase ascii wide
        $string22_tightvnc_greyware_tool_keyword = /tvnserver\.exe/ nocase ascii wide
        $string23_tightvnc_greyware_tool_keyword = /tvnviewer\.exe/ nocase ascii wide
        $string24_tightvnc_greyware_tool_keyword = /VncViewer\.Config/ nocase ascii wide
        $string25_tightvnc_greyware_tool_keyword = /www\.tightvnc\.com\/download\/.{0,100}\=/ nocase ascii wide
        
        $string1_ssh_greyware_tool_keyword = "bad client public DH value" nocase ascii wide
        $string2_ssh_greyware_tool_keyword = "fatal: buffer_get_string: bad string" nocase ascii wide
        $string3_ssh_greyware_tool_keyword = "Local: crc32 compensation attack" nocase ascii wide
        $string4_ssh_greyware_tool_keyword = "nano /etc/ssh/sshd_config" nocase ascii wide
        $string5_ssh_greyware_tool_keyword = /ssh\.exe\s\-L\s0\.0\.0\.0\:445\:127\.0\.0\.1\:445\s/ nocase ascii wide
        $string6_ssh_greyware_tool_keyword = "vim /etc/ssh/sshd_config" nocase ascii wide
        
        $string1_rmdir__greyware_tool_keyword = /rd\s\/s\s\/q\s\%systemdrive\%\\\$RECYCLE\.BIN/ nocase ascii wide
         
        $string1_advanced_ip_scanner_greyware_tool_keyword = /\.exe\s\/s\:ip_ranges\.txt\s\/f\:scan_results\.txt/ nocase ascii wide
        $string2_advanced_ip_scanner_greyware_tool_keyword = /\\Advanced\sIP\sScanner\.lnk/ nocase ascii wide
        $string3_advanced_ip_scanner_greyware_tool_keyword = /\\advanced_ip_scanner/ nocase ascii wide
        $string4_advanced_ip_scanner_greyware_tool_keyword = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
        $string5_advanced_ip_scanner_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
        $string6_advanced_ip_scanner_greyware_tool_keyword = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
        $string7_advanced_ip_scanner_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Advanced\sIP\sScanner\sv2/ nocase ascii wide
        $string8_advanced_ip_scanner_greyware_tool_keyword = ">Advanced IP Scanner Setup<" nocase ascii wide
        $string9_advanced_ip_scanner_greyware_tool_keyword = ">Advanced IP Scanner<" nocase ascii wide
        $string10_advanced_ip_scanner_greyware_tool_keyword = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b" nocase ascii wide
        $string12_advanced_ip_scanner_greyware_tool_keyword = "Advanced IP Scanner" nocase ascii wide
        $string13_advanced_ip_scanner_greyware_tool_keyword = /Advanced_IP_Scanner.{0,100}\.exe/ nocase ascii wide
        $string14_advanced_ip_scanner_greyware_tool_keyword = /advanced_ip_scanner_console\.exe/ nocase ascii wide
        $string15_advanced_ip_scanner_greyware_tool_keyword = /https\:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,100}\.exe/ nocase ascii wide
        
        $string1_myexternalip_com_greyware_tool_keyword = /https\:\/\/myexternalip\.com\/raw/ nocase ascii wide
        
        $string1_dd_greyware_tool_keyword = "dd if=/dev/nul" nocase ascii wide
        $string2_dd_greyware_tool_keyword = "dd if=/dev/zero" nocase ascii wide
        
         
        
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        (((filesize < 20MB and (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or uint32(0) == 0x504B0304 or uint32(0) == 0xCAFEBABE or uint32(0) == 0x4D534346 or uint32(0) == 0xD0CF11E0 or uint16(0) == 0x2321 or uint16(0) == 0x3c3f)) and any of ($string*)) or (filesize < 2MB and (any of ($string*) and for any of ($metadata_regex_*) : ( @ <= 20000 ))))
  
}
