import "pe"

rule Neshta {
   strings:
        $dlph = "SOFTWARE\\Borland\\Delphi\\RTL"
        $nshta1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus"
        $nshta2 = "Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]"
        
        $x1 = "the best. Fuck off all the rest."
        $x2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii

        $s1 = "Neshta" ascii fullword
        $s2 = "Made in Belarus. " ascii fullword

        $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
        $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
        $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }

        $sop1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
        $sop2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }
      
        $a1 = { 44 65 6C 70 68 69 2D 74 68 65 20 62 65 73 74 2E 20 46 75 63 6B 20 6F 66 66 20 61 6C 6C 20 74 68 65 20 72 65 73 74 2E 20 4E 65 73 68 74 61 20 31 2E 30 20 4D 61 64 65 20 69 6E 20 42 65 6C 61 72 75 73 2E }
	      $a2 = { 55 8B EC 81 C4 64 FF FF FF 53 56 57 33 D2 89 95 64 FF FF FF 8B F8 33 C0 55 68 FC 6D 40 00 64 FF 30 64 89 20 8D 85 69 FF FF FF 50 68 97 00 00 00 E8 1B D3 FF FF 33 DB EB 5C 8B F3 81 E6 FF 00 00 }
	
	
    condition:
        
        (pe.locale(0x0419) //(RU)
        and $dlph 
        and any of ($nshta*)) or
        (uint16(0) == 0x5a4d and
      filesize < 3000KB and (
         1 of ($x*) or 
         all of ($s*) or 
         3 of them)) or
      	(any of($a*))
}
