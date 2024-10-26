rule Reverse_engenering {
	
	strings:
		//anti debug
		$lib_kernel32 = "Kernel32.dll" nocase
        	$func = "CheckRemoteDebuggerPresent" 
		$func1 = "IsDebuggerPresent" 
		$func2 = "OutputDebugString" 
		$func3 = "ContinueDebugEvent" 
		$func4 = "DebugActiveProcess"
		
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
		
		
		
    	condition:
        	($lib_kernel32 and 1 of ($func*)) or
        	(any of ($proc_tool*)) or
        	(any of ($vm*)) or
        	()

}
