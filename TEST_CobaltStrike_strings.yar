rule TEST_CobaltStrike_strings
{
    strings:
        $enc_beacon_x86_1 = { fc e8 ?? 00 00 00 }
        $enc_beacon_x86_2 = { 8b [1-3] 83 c? 04 [0-1] 8b [1-2] 31 }  
        
        $enc_beacon_x86_64 = { fc 48 83 e4 f0 eb 33 5d 8b 45 00 48 83 c5 04 8b }      
        
        $sleep_mask = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 45 33 DB 45 33 D2 33 FF 33 F6 48 8B E9 BB 03 00 00 00 85 D2 0F 84 81 00 00 00 0F B6 45 }
        
        $artifact_beacon = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
        
        $gifmagic = { 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 FF FF FF 21 F9 04 01 00 00 00 2C 00 00 00 00 01 00 01 00 00 02 01 44 00 3B }
        
        $cobaltStrikeRule64 = {  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 (00|01|02|04|08|10) 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00  01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 } 
        $cobaltStrikeRule32 = {  00 00 00 00 00 00 00 00  01 00 00 00 (00|01|02|04|08|10) 00 00 00 01 00 00 00 ?? ?? 00 00  02 00 00 00 ?? ?? ?? ??  02 00 00 00 ?? ?? ?? ??  01 00 00 00 ?? ?? 00 00 }
        
        $a_x64 = {89 C2 45 09 C2 74 1F 41 39 C0 76 E9 4C 8B 13 49 89 C3 41 83 E3 07 49 01 C2 46 8A 5C 1B 10 48 FF C0 45 30 1A}
        
        
        $a1 = "VBScript" nocase ascii
		$a2 = "var_func()" nocase ascii
		$a3 = "var_shell" nocase ascii
		$a4 = "Wscript.Shell" nocase ascii
		$a5 = "powershell" nocase ascii
		$a6 = "hidden" nocase ascii
		$a7 = "-enc" nocase ascii
		$a8 = "-nop" nocase ascii
    condition:
        ($enc_beacon_x86_1 at 0 and $enc_beacon_x86_2 in (0..200) and filesize < 300000) or 
        ($enc_beacon_x86_64 at 0 and filesize < 300000) or
        ($sleep_mask) or
        ($artifact_beacon) or
        (filesize > 10KB and $gifmagic at 0) or
        ($cobaltStrikeRule64 or $cobaltStrikeRule32) or
        ($a_x64) or
        (6 of ($a*))        
}
