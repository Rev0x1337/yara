rule TEST_Sliver
{
    strings:
        $s_tcppivot32 = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }
        $s_wg32 = { 66 81 ?? 77 67 }
        $s_dns32 = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
        $s_http32 = { 81 ?? 68 74 74 70 }
        $s_https32 = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }
        $s_mtls32 = { 81 ?? 6D 74 6C 73 }
        $fp132 = "cloudfoundry" ascii fullword
        
        $a_tcppivot64 = { 48 ?? 74 63 70 70 69 76 6F 74 }
        $a_namedpipe64 = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }
        $a_https64 = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }
        $a_wg64 = {66 81 ?? 77 67}
        $a_dns64 = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }
        $a_mtls64 = {  81 ?? 6D 74 6C 73  }
    condition:
        (4 of ($s*) and not 1 of ($fp*)) or 
        (5 of ($a*) and not 1 of ($fp*))
}
