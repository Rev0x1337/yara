rule TEST_CobaltStrike_beacon
{
    strings:
       
       
        
        
      
        $s7 = { 2e 2f 2e 2f 2e 2c ?? ?? 2e 2c 2e 2f }
        $s8 = { 69 68 69 68 69 6b ?? ?? 69 6b 69 68 }
        
        $s10 = "Updater.dll" ascii
        $s11 = "LibTomMath" ascii
        $s12 = "Content-Type: application/octet-stream" ascii
        
    condition:
        6 of them and filesize < 300000    
}        

