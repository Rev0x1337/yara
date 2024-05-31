rule TEST_CobaltStrike_trojan
{
    strings:
        $bypass1 = "bypassuac.dll" ascii fullword
        $bypass2 = "bypassuac.x64.dll" ascii fullword
        $bypass3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $Sys1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $Sys2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $Sys3 = "[*] Cleanup successful" ascii fullword
        $Sys4 = "\\System32\\cliconfg.exe" wide fullword
        $Sys5 = "\\System32\\eventvwr.exe" wide fullword
        $Sys6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $Sys7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $Sys8 = "\\System32\\sysprep\\" wide fullword
        $Sys9 = "[-] COM initialization failed." ascii fullword
        $Sys10 = "[-] Privileged file copy failed: %S" ascii fullword
        $Sys11 = "[-] Failed to start %S: %d" ascii fullword
        $Sys12 = "ReflectiveLoader"
        $Sys13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $Sys14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $Sys15 = "[+] %S ran and exited." ascii fullword
        $Sys16 = "[+] Privileged file copy success! %S" ascii fullword  
        
        $key1 = "keylogger.dll" ascii fullword
        $key2 = "keylogger.x64.dll" ascii fullword
        $key3 = "\\\\.\\pipe\\keylogger" ascii fullword
        $key4 = "%cE=======%c" ascii fullword
        $key5 = "[unknown: %02X]" ascii fullword
        $Load1 = "ReflectiveLoader"
        $Load2 = "%c2%s%c" ascii fullword
        $Load3 = "[numlock]" ascii fullword
        $Load4 = "%cC%s" ascii fullword
        $Load5 = "[backspace]" ascii fullword
        $Load6 = "[scroll lock]" ascii fullword
        $Load7 = "[control]" ascii fullword
        $Load8 = "[left]" ascii fullword
        $Load9 = "[page up]" ascii fullword
        $Load10 = "[page down]" ascii fullword
        $Load11 = "[prtscr]" ascii fullword
        $Load12 = "ZRich9" ascii fullword
        $Load13 = "[ctrl]" ascii fullword
        $Load14 = "[home]" ascii fullword
        $Load15 = "[pause]" ascii fullword
        $Load16 = "[clear]" ascii fullword  
        
        $dll1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
        $dll2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
        $Err1 = "__imp_BeaconErrorDD" ascii fullword
        $Err2 = "__imp_BeaconErrorNA" ascii fullword
        $Err3 = "__imp_BeaconErrorD" ascii fullword
        $Err4 = "__imp_BeaconDataInt" ascii fullword
        $Err5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
        $Err6 = "__imp_KERNEL32$OpenProcess" ascii fullword
        $Err7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
        $Err8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
        
        $get1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
        $get2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
        $fail1 = "getsystem failed." ascii fullword
        $fail2 = "_isSystemSID" ascii fullword
        $fail3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
        $Inf1 = "getsystem failed." ascii fullword
        $Inf2 = "$pdata$isSystemSID" ascii fullword
        $Inf3 = "$unwind$isSystemSID" ascii fullword
        $Inf4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
        
        $hash1 = "hashdump.dll" ascii fullword
        $hash2 = "hashdump.x64.dll" ascii fullword
        $hash3 = "\\\\.\\pipe\\hashdump" ascii fullword
        $hash4 = "ReflectiveLoader"
        $hash5 = "Global\\SAM" ascii fullword
        $hash6 = "Global\\FREE" ascii fullword
        $hash7 = "[-] no results." ascii fullword
        
        $inter1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
        $inter2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
        $imp1 = "__imp_BeaconFormatAlloc" ascii fullword
        $imp2 = "__imp_BeaconFormatPrintf" ascii fullword
        $imp3 = "__imp_BeaconOutput" ascii fullword
        $imp4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
        $imp5 = "__imp_KERNEL32$LocalFree" ascii fullword
        $imp6 = "__imp_LoadLibraryA" ascii fullword
        
        $inv1 = "invokeassembly.x64.dll" ascii fullword
        $inv2 = "invokeassembly.dll" ascii fullword
        $Ref1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $Ref2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $Ref3 = "[-] Failed to create the runtime host" ascii fullword
        $Ref4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $Ref5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $Ref6 = "ReflectiveLoader"
        $Ref7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $Ref8 = "[-] No .NET runtime found. :(" ascii fullword
        $Ref9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
        
        $kerb1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
        $kerb2 = "$unwind$command_kerberos_ticket_use" ascii fullword
        $kerb3 = "$pdata$command_kerberos_ticket_use" ascii fullword
        $kerb4 = "command_kerberos_ticket_use" ascii fullword
        $kerb5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
        $kerb6 = "command_kerberos_ticket_purge" ascii fullword
        $kerb7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
        $kerb8 = "$unwind$kerberos_init" ascii fullword
        $kerb9 = "$unwind$KerberosTicketUse" ascii fullword
        $kerb10 = "KerberosTicketUse" ascii fullword
        $kerb11 = "$unwind$KerberosTicketPurge" ascii fullword
        $ker1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
        $ker2 = "_command_kerberos_ticket_use" ascii fullword
        $ker3 = "_command_kerberos_ticket_purge" ascii fullword
        $ker4 = "_kerberos_init" ascii fullword
        $ker5 = "_KerberosTicketUse" ascii fullword
        $ker6 = "_KerberosTicketPurge" ascii fullword
        $ker7 = "_LsaCallKerberosPackage" ascii fullword
        
        $mim1 = "\\\\.\\pipe\\mimikatz" ascii fullword
        $lsa1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
        $lsa2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
        $lsa3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
        $lsa4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
        $lsa5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
        $lsa6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
        $lsa7 = "mimikatz(powershell) # %s" wide fullword
        $lsa8 = "powershell_reflective_mimikatz" ascii fullword
        $lsa9 = "mimikatz_dpapi_cache.ndr" wide fullword
        $lsa10 = "mimikatz.log" wide fullword
        $lsa11 = "ERROR mimikatz_doLocal" wide
        $lsa12 = "mimikatz_x64.compressed" wide
        
        $net1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
        $net2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
        $Pr1 = "__imp_BeaconPrintf" ascii fullword
        $Pr2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
        $Pr3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
        $Be1 = "__imp__BeaconPrintf" ascii fullword
        $Be2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
        $Be3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
        
        $view1 = "netview.x64.dll" ascii fullword
        $view2 = "netview.dll" ascii fullword
        $view3 = "\\\\.\\pipe\\netview" ascii fullword
        $Pa1 = "Sessions for \\\\%s:" ascii fullword
        $Pa2 = "Account information for %s on \\\\%s:" ascii fullword
        $Pa3 = "Users for \\\\%s:" ascii fullword
        $Pa4 = "Shares at \\\\%s:" ascii fullword
        $Pa5 = "ReflectiveLoader" ascii fullword
        $Pa6 = "Password changeable" ascii fullword
        $Pa7 = "User's Comment" wide fullword
        $Pa8 = "List of hosts for domain '%s':" ascii fullword
        $Pa9 = "Password changeable" ascii fullword
        $Pa10 = "Logged on users at \\\\%s:" ascii fullword
        
        $port1 = "portscan.x64.dll" ascii fullword
        $port2 = "portscan.dll" ascii fullword
        $port3 = "\\\\.\\pipe\\portscan" ascii fullword
        $Tar1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $Tar2 = "(ARP) Target '%s' is alive. " ascii fullword
        $Tar3 = "TARGETS!12345" ascii fullword
        $Tar4 = "ReflectiveLoader" ascii fullword
        $Tar5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $Tar6 = "Scanner module is complete" ascii fullword
        $Tar7 = "pingpong" ascii fullword
        $Tar8 = "PORTS!12345" ascii fullword
        $Tar9 = "%s:%d (%s)" ascii fullword
        $Tar10 = "PREFERENCES!12345" ascii fullword
        
        $post1 = "postex.x64.dll" ascii fullword
        $post2 = "postex.dll" ascii fullword
        $post3 = "RunAsAdminCMSTP" ascii fullword
        $post4 = "KerberosTicketPurge" ascii fullword
        $ber1 = "GetSystem" ascii fullword
        $ber2 = "HelloWorld" ascii fullword
        $ber3 = "KerberosTicketUse" ascii fullword
        $ber4 = "SpawnAsAdmin" ascii fullword
        $ber5 = "RunAsAdmin" ascii fullword
        $ber6 = "NetDomain" ascii fullword
        
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
        
        $shell1 = "PowerShellRunner.dll" wide fullword
        $shell2 = "powershell.x64.dll" ascii fullword
        $shell3 = "powershell.dll" ascii fullword
        $shell4 = "\\\\.\\pipe\\powershell" ascii fullword
        $Run1 = "PowerShellRunner.PowerShellRunner" ascii fullword
        $Run2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
        $Run3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $Run4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
        $Run5 = "CustomPSHostUserInterface" ascii fullword
        $Run6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
        $Run7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $pdb1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
        $pdb2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
        
        $pse1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
        $pse2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
        $Pars1 = "__imp_BeaconDataExtract" ascii fullword
        $Pars2 = "__imp_BeaconDataParse" ascii fullword
        $Pars3 = "__imp_BeaconDataParse" ascii fullword
        $Pars4 = "__imp_BeaconDataParse" ascii fullword
        $Pars5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
        $Pars6 = "__imp_ADVAPI32$DeleteService" ascii fullword
        $Pars7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
        $Pars8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
        $Dat1 = "__imp__BeaconDataExtract" ascii fullword
        $Dat2 = "__imp__BeaconDataParse" ascii fullword
        $Dat3 = "__imp__BeaconDataParse" ascii fullword
        $Dat4 = "__imp__BeaconDataParse" ascii fullword
        $Dat5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
        $Dat6 = "__imp__ADVAPI32$DeleteService" ascii fullword
        $Dat7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
        $Dat8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
        
        $reg1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
        $reg2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
        $All1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
        $All2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
        $All3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
        $All4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
        $All5 = "__imp_BeaconFormatAlloc" ascii fullword
        $All6 = "__imp_BeaconOutput" ascii fullword
        $All7 = "__imp_BeaconFormatFree" ascii fullword
        $All8 = "__imp_BeaconDataPtr" ascii fullword
        $con1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
        $con2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
        $con3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
        $con4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
        $con5 = "__imp__BeaconFormatAlloc" ascii fullword
        $con6 = "__imp__BeaconOutput" ascii fullword
        $con7 = "__imp__BeaconFormatFree" ascii fullword
        $con8 = "__imp__BeaconDataPtr" ascii fullword
        
        $scr1 = "screenshot.x64.dll" ascii fullword
        $scr2 = "screenshot.dll" ascii fullword
        $scr3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $Des1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $Des2 = "GetDesktopWindow" ascii fullword
        $Des3 = "CreateCompatibleBitmap" ascii fullword
        $Des4 = "GDI32.dll" ascii fullword
        $Des5 = "ReflectiveLoader"
        $Des6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
        
        $ssh1 = "sshagent.x64.dll" ascii fullword
        $ssh2 = "sshagent.dll" ascii fullword
        $pipe1 = "\\\\.\\pipe\\sshagent" ascii fullword
        $pipe2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword
        
        $time1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
        $time2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
        $Ext1 = "__imp_KERNEL32$GetFileTime" ascii fullword
        $Ext2 = "__imp_KERNEL32$SetFileTime" ascii fullword
        $Ext3 = "__imp_KERNEL32$CloseHandle" ascii fullword
        $Ext4 = "__imp_KERNEL32$CreateFileA" ascii fullword
        $Ext5 = "__imp_BeaconDataExtract" ascii fullword
        $Ext6 = "__imp_BeaconPrintf" ascii fullword
        $Ext7 = "__imp_BeaconDataParse" ascii fullword
        $Ext8 = "__imp_BeaconDataExtract" ascii fullword
        $File1 = "__imp__KERNEL32$GetFileTime" ascii fullword
        $File2 = "__imp__KERNEL32$SetFileTime" ascii fullword
        $File3 = "__imp__KERNEL32$CloseHandle" ascii fullword
        $File4 = "__imp__KERNEL32$CreateFileA" ascii fullword
        $File5 = "__imp__BeaconDataExtract" ascii fullword
        $File6 = "__imp__BeaconPrintf" ascii fullword
        $File7 = "__imp__BeaconDataParse" ascii fullword
        $File8 = "__imp__BeaconDataExtract" ascii fullword
        
        $uac1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
        $uac2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
        $cms1 = "elevate_cmstp" ascii fullword
        $cms2 = "$pdata$elevate_cmstp" ascii fullword
        $cms3 = "$unwind$elevate_cmstp" ascii fullword
        $ele1 = "_elevate_cmstp" ascii fullword
        $ele2 = "__imp__OLE32$CoGetObject@16" ascii fullword
        $ele3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
        $ele4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
        $ele5 = "OLDNAMES"
        $ele6 = "__imp__BeaconDataParse" ascii fullword
        $ele7 = "_willAutoElevate" ascii fullword
        
        $token1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
        $token2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
        $token3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
        $token4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
        $admin1 = "$pdata$is_admin_already" ascii fullword
        $admin2 = "$unwind$is_admin" ascii fullword
        $admin3 = "$pdata$is_admin" ascii fullword
        $admin4 = "$unwind$is_admin_already" ascii fullword
        $admin5 = "$pdata$RunAsAdmin" ascii fullword
        $admin6 = "$unwind$RunAsAdmin" ascii fullword
        $admin7 = "is_admin_already" ascii fullword
        $admin8 = "is_admin" ascii fullword
        $admin9 = "process_walk" ascii fullword
        $admin10 = "get_current_sess" ascii fullword
        $admin11 = "elevate_try" ascii fullword
        $admin12 = "RunAsAdmin" ascii fullword
        $admin13 = "is_ctfmon" ascii fullword
        $is1 = "_is_admin_already" ascii fullword
        $is2 = "_is_admin" ascii fullword
        $is3 = "_process_walk" ascii fullword
        $is4 = "_get_current_sess" ascii fullword
        $is5 = "_elevate_try" ascii fullword
        $is6 = "_RunAsAdmin" ascii fullword
        $is7 = "_is_ctfmon" ascii fullword
        $is8 = "_reg_query_dword" ascii fullword
        $is9 = ".drectve" ascii fullword
        $is10 = "_is_candidate" ascii fullword
        $is11 = "_SpawnAsAdmin" ascii fullword
        $is12 = "_SpawnAsAdminX64" ascii fullword
        
        $bin1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $bin2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
        
        $ab1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
        $ab2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
        
        $abc1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $abc2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
        
        $abc3 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
        
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
        
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
                        
        $sleep1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
        $sleep2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
        $sleep3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
        $sleep4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
        $sleep5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
        $sleep6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword
        
        $brow1 = "browserpivot.dll" ascii fullword
        $brow2 = "browserpivot.x64.dll" ascii fullword
        $pivot1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
        $pivot2 = "COBALTSTRIKE" ascii fullword
        
        $wmi1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
        $wmi2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword
        
        $stri = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }
        
        $acb1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $acb2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $acb3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $acb4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $acb5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
        
        $acbd1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
        $acbd2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }
        
        $bac1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $bac2 = "%s as %s\\%s: %d" fullword
        
        $astr = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }
    condition:
        (2 of ($bypass*) or 10 of ($Sys*)) or
        (1 of ($key*) and 14 of ($Load*)) or
        (1 of ($dll*) or 5 of ($Err*)) or
        (1 of ($get*) or 3 of ($fail*) or 3 of ($Inf*)) or
        (4 of ($hash*)) or
        (1 of ($inter*) or 4 of ($imp*)) or
        (1 of ($inv*) or 3 of ($Ref*) or $c1) or
        (5 of ($kerb*) or 3 of ($ker*)) or
        ($mim1 and 7 of ($lsa*)) or
        (1 of ($net*) or 2 of ($Pr*) or 2 of ($Be*)) or
        (2 of ($view*) or 6 of ($Pa*)) or
        (2 of ($port*) or 6 of ($Tar*)) or
        (2 of ($post*) or 4 of ($ber*)) or
        (6 of ($a*)) or
        ((1 of ($shell*) and 4 of ($Run*)) or 1 of ($pdb*)) or 
        (1 of ($pse*) or 5 of ($Pars*) or 5 of ($Dat*)) or
        (1 of ($reg*) or 5 of ($All*) or 5 of ($con*)) or
        (2 of ($scr*) or 5 of ($Des*)) or
        (1 of ($ssh*) and 1 of ($pipe*)) or
        (1 of ($time*) or 5 of ($Ext*) or 5 of ($File*)) or
        (1 of ($uac*) or 3 of ($cms*) or 4 of ($ele*)) or 
        (1 of ($token*) or 9 of ($admin*) or 7 of ($is*)) or 
        (1 of ($bin*)) or
        ($ab1 and $ab2) or 
        ($abc1 and $abc2) or $abc3 or
        ($a_x64 or $a_x64_smbtcp or $a_x86 or $a_x86_2 or $a_x86_smbtcp) or
        ($beacon_loader_x64 or $beacon_loader_x86 or $beacon_loader_x86_2 or $generic_loader_x64 or $generic_loader_x86) or
        ($sleep1 or $sleep2 or $sleep3 or $sleep4 or $sleep5 or $sleep6) or 
        (1 of ($brow*) and 2 of ($pivot*)) or
        (1 of ($wmi*)) or 
        $stri or 
        (1 of ($acb*)) or 
        ($acbd1 and $acbd2) or 
        ($bac1 and $bac2) or 
        ($astr) 
}
