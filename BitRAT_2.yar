rule BitRAT_2
{
    strings:
        $httpn  = /(aHR\x30cDovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwOi\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHA\x36Ly[\x2b\x2f\x38-\x39])/
	$httpw  = /(aAB\x30AHQAcAA\x36AC\x38AL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAOgAvAC[\x2b\x2f\x38-\x39])/
	$httpsn = /(aHR\x30cHM\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]odHRwczovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x32GWm]h\x30dHBzOi\x38v[\x2b\x2f-\x39A-Za-z])/
    $httpsw = /(aAB\x30AHQAcABzADoALwAv[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]oAHQAdABwAHMAOgAvAC[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x32GWm]gAdAB\x30AHAAcwA\x36AC\x38AL[\x2b\x2f-\x39w-z])/
    
        $magic  = "INQUEST-PII="
	$api_00 = "LoadLibraryA" nocase ascii wide
    $api_01 = "ShellExecuteA" nocase ascii wide
    $api_03 = "GetProcAddress" nocase ascii wide
    $api_04 = "GetVersionExA" nocase ascii wide
    $api_05 = "GetModuleHandleA" nocase ascii wide
    $api_06 = "OpenProcess" nocase ascii wide
    $api_07 = "GetWindowsDirectoryA" nocase ascii wide
    $api_08 = "lstrcatA" nocase ascii wide
    $api_09 = "GetSystemDirectoryA" nocase ascii wide
    $api_10 = "WriteFile" nocase ascii wide
    $api_11 = "ReadFile" nocase ascii wide
    $api_12 = "GetFileSize" nocase ascii wide
    $api_13 = "CreateFileA" nocase ascii wide
    $api_14 = "DeleteFileA" nocase ascii wide
    $api_15 = "CreateProcessA" nocase ascii wide
    $api_16 = "GetCurrentProcessId" nocase ascii wide
    $api_17 = "RegOpenKeyExA" nocase ascii wide
    $api_18 = "GetStartupInfoA" nocase ascii wide
    $api_19 = "CreateServiceA" nocase ascii wide
    $api_20 = "CopyFileA" nocase ascii wide
    $api_21 = "GetModuleFileNameA" nocase ascii wide
    $api_22 = "IsBadReadPtr" nocase ascii wide
    $api_23 = "CreateFileW" nocase ascii wide
    $api_24 = "SetFilePointer" nocase ascii wide
    $api_25 = "VirtualAlloc" nocase ascii wide
    $api_26 = "AdjustTokenPrivileges" nocase ascii wide
    $api_27 = "CloseHandle" nocase ascii wide
    $api_28 = "CreateFile" nocase ascii wide
    $api_29 = "GetProcAddr" nocase ascii wide
    $api_30 = "GetSystemDirectory" nocase ascii wide
    $api_31 = "GetTempPath" nocase ascii wide
    $api_32 = "GetWindowsDirectory" nocase ascii wide
    $api_33 = "IsBadReadPtr" nocase ascii wide
    $api_34 = "IsBadWritePtr" nocase ascii wide
    $api_35 = "LoadLibrary" nocase ascii wide
    $api_36 = "ReadFile" nocase ascii wide
    $api_37 = "SetFilePointer" nocase ascii wide
    $api_38 = "ShellExecute" nocase ascii wide
    $api_39 = "UrlDownloadToFile" nocase ascii wide
    $api_40 = "WinExec" nocase ascii wide
    $api_41 = "WriteFile" nocase ascii wide
    $api_42 = "StartServiceA" nocase ascii wide
    $api_43 = "VirtualProtect" nocase ascii wide
    condition:
        (any of ($http*) and not (uint16be(0x0) == 0x4d5a)) or
        (any of ($api*)
    and not $magic in (filesize-30..filesize)
    and not 
    (
        /* trigger = 'MZ' */
        (uint16be(0x0) == 0x4d5a)
        or
        /* trigger = 'ZM' */
        (uint16be(0x0) == 0x5a4d)
        or
        /* trigger = 'PE' */
        (uint16be(uint32(0x3c)) == 0x5045)
    ))

}
