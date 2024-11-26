rule Reverse_engenering {
	
	strings:
		//anti debug
        	$deb0 = "CheckRemoteDebuggerPresent" 
		$deb1 = "IsDebuggerPresent" 
		$deb2 = "OutputDebugString" 
		$deb3 = "ContinueDebugEvent" 
		$deb4 = "DebugActiveProcess"
		
		//anti debug tools
		$proc_tool0 = "procexp.exe" nocase
		$proc_tool1 = "procmon.exe" nocase
		$proc_tool2 = "processmonitor.exe" nocase
		$proc_tool3 = "wireshark.exe" nocase
		$proc_tool4 = "fiddler.exe" nocase
		$proc_tool5 = "windbg.exe" nocase
		$proc_tool6 = "ollydbg.exe" nocase
		$proc_tool7 = "winhex.exe" nocase       
		$proc_tool8 = "processhacker.exe" nocase
		$proc_tool9 = "hiew32.exe" nocase
		$proc_tool10 = "x64dbg.exe" nocase
		$proc_tool11 = "ida.exe" nocase
		
		//anti virtual machine
		$vm0 = "VBoxService.exe" nocase
		$vm1 = "vmware.exe" nocase
		$vm2 = "vmware-authd.exe" nocase
		$vm3 = "vmware-hostd.exe" nocase
		$vm4 = "vmware-tray.exe" nocase
		$vm5 = "vmware-vmx.exe" nocase
		$vm6 = "vmnetdhcp.exe" nocase
		$vm7 = "vpxclient.exe" nocase
	    	$vm8 = { b868584d56bb00000000b90a000000ba58560000ed }
		
		//win_hook
		$usr32 = "user32.dll" nocase
        	$hook1 = "UnhookWindowsHookEx"
        	$hook2 = "SetWindowsHookExA"
       		$hook3 = "CallNextHookEx"  

		//File operation
		$krn32 = "kernel32.dll" nocase
	        $fop1 = "WriteFile"
	        $fop2 = "SetFilePointer"
	        $fop3 = "WriteFile"
	        $fop4 = "ReadFile"
	        $fop5 = "DeleteFileA"
	        $fop6 = "CreateFileA"
	        $fop7 = "FindFirstFileA"
	        $fop8 = "MoveFileExA"
	        $fop9 = "FindClose"
	        $fop10 = "SetFileAttributesA"
	        $fop11 = "CopyFile"

		//Win private profile
		$pp1 = "GetPrivateProfileIntA"
	        $pp2 = "GetPrivateProfileStringA"
	        $pp3 = "WritePrivateProfileStringA"

		//Win_token
		$adv32 = "advapi32.dll" nocase
	        $token1 = "DuplicateTokenEx"
	        $token2 = "AdjustTokenPrivileges"
	        $token3 = "OpenProcessToken"
	        $token4 = "LookupPrivilegeValueA" 

		//Win_reg
		$reg1 = "RegQueryValueExA"
	        $reg2 = "RegOpenKeyExA"
	        $reg3 = "RegCloseKey"
	        $reg4 = "RegSetValueExA"
	        $reg5 = "RegCreateKeyA"
	        $reg6 = "RegCloseKey"

		//Win_mutex
		$mutex = "CreateMutex"

		//check_patchlevel
		$hotfix = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase

		//rat_webcam
		$avcp32 = "avicap32.dll" nocase
        	$captwin = "capCreateCaptureWindow" nocase

		//rat_telnet
		$telserv = "software\\microsoft\\telnetserver" nocase

		//rat_rdp
		$ratrdp0 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
	        $ratrdp1 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
	        $ratrdp2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
	        $ratrdp3 = "EnableAdminTSRemote"
	        $ratrdp4 = "net start termservice"
	        $ratrdp5 = "sc config termservice start"

		//rat_vnc
		$ratvnc1 = "ultravnc.ini" nocase
	        $ratvnc2 = "StartVNC" 
        	$ratvnc3 = "StopVNC" 

		//spreading_share
		$netapi32 = "netapi32.dll" nocase
	        $netshare1 = "NetShareGetInfo" 
	        $netshare2 = "NetShareEnum" 

		//spreading_file
		$sprfile1 = "autorun.inf" nocase
	        $sprfile2 = "desktop.ini" nocase
	        $sprfile3 = "desktop.lnk" nocase

		//migrate_apc
		$migrapc1 = "OpenThread" 
         	$migrapc2 = "QueueUserAPC"

		//sniff_lan
		$snifflan1 = "packet.dll" nocase
	        $snifflan2 = "npf.sys" nocase
	        $snifflan3 = "wpcap.dll" nocase
	        $snifflan4 = "winpcap.dll" nocase

		//steal_cred
		$cript32 = "Crypt32.dll" nocase
	        $stealcred1 = "CryptUnprotectData" 
	        $stealcred2 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase

		//cred_vnc
		$credvnc = "VNCPassView"

		//cred_firefox
		$credfirefox1 = "signons.sqlite"
	        $credfirefox2 = "signons3.txt"
	        $credfirefox3 = "secmod.db"
	        $credfirefox4 = "cert8.db"
	        $credfirefox5 = "key3.db"

		//sniff_audio
		$winmn = "winmm.dll" nocase
	        $snifaud1 = "waveInStart"
	        $snifaud2 = "waveInReset"
	        $snifaud3 = "waveInAddBuffer"
	        $snifaud4 = "waveInOpen"
	        $snifaud5 = "waveInClose"

		//cred local
		$credloc1 = "LsaEnumerateLogonSessions"
	        $credloc2 = "SamIConnect"
	        $credloc3 = "SamIGetPrivateData"
	        $credloc4 = "SamQueryInformationUse"
	        $credloc5 = "CredEnumerateA"
	        $credloc6 = "CredEnumerateW"
	        $credloc7 = "software\\microsoft\\internet account manager" nocase
	        $credloc8 = "software\\microsoft\\identitycrl\\creds" nocase
	        $credloc9 = "Security\\Policy\\Secrets"

		//keylogger
		$keylogger1 = "GetAsyncKeyState" 
	        $keylogger2 = "GetKeyState" 
	        $keylogger3 = "MapVirtualKey" 
	        $keylogger4 = "GetKeyboardType"

    	condition:
        	($krn32 and 1 of ($deb*)) or
        	(any of ($proc_tool*)) or
        	(any of ($vm*)) or
        	($usr32 and 1 of ($hook*)) or
		($krn32 and 3 of ($fop*)) or
		($krn32 and 1 of ($pp*)) or
		($adv32 and 1 of ($token*)) or
		($adv32 and 1 of ($reg*)) or
		($mutex) or ($hotfix) or
		($avcp32 and $captwin) or
		($telserv) or (1 of ($ratrdp*)) or
		(any of ($ratvnc*)) of
		($netapi32 and 1 of ($netshare*)) of
		(any of ($sprfile*)) or (2 of ($migrapc*)) or
		(any of ($snifflan*)) or
		($cript32 and 2 ($stealcred*)) or ($credvnc) or
		(any of ($credfirefox*)) of ($winmn and 2 of ($snifaud*)) of
		(any of ($credloc*)) of ($usr32 and 1 of ($keylogger*)) 

}
