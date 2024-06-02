rule RustyStealer {
    
    strings:
        $s1 = "EdgeMicrosoftedgechromiumChromium7star7StaramigoAmigobraveBrave" ascii
        $s2 = "BrowserchromeChromekometaKometaorbitumOrbitumsputnikSputniktorchTorchucozmediaUranuCozMediavivaldiVivaldiatom" ascii
        $s3 = ".kdbx.pdf.doc.docx.xls.xlsx.ppt.pptx.odt.odp\\logscx\\sensfiles.zip" ascii
        $s4 = "dumper.rs" ascii
        $s5 = "decryption_core.rs" ascii
        $s6 = "anti_emulation.rs" ascii
        $s7 = "discord.rs" ascii
        $s8 = /\\logscx\\(passwords_|cookies_|creditcards_)/ ascii
        $s9 = "VirtualBoxVBoxVMWareVMCountry" ascii
        $s10 = "New Log From ( /  )" ascii
        $s11 = "BrowserChromeKometaOrbitumSputnikTorchUranuCozMediaVivaldiAtomMail" ascii
        $s12 = "BrowserBraveSoftwareCentBrowserChedotChrome" ascii
        $s13 = "ChromeKometaOrbitumSputnikTorchUranuCozMediaVivaldi" ascii
        $s14 = "hostnameencryptedUsernameencryptedPasswordstruct" ascii
        $s15 = "encryptedPassword" fullword ascii
        $s16 = "AutoFill@~" fullword ascii
        
        $a_01_0 = {c7 45 fc 19 00 00 00 8b c3 0f b6 0e f7 75 fc 41 0f af cb 8a 44 15 d8 30 81 77 af 00 10 43 }
        
        $rusti1 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\alloc\\src\\collections\\btree\\map\\entry.rsh"
        $rusti2 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\slice\\iter.rs"
        $rusti3 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\fmt\\mod.rs"
        $rusti4 = "G:\\RUST_DROPPER_EXE_PAYLOAD\\DROPPER_MAIN\\pe-tools\\src\\shared"
        $rusti5 = "G:\\RUST_DROPPER_EXE_PAYLOAD\\DROPPER_MAIN\\pe-tools\\src\\x64.rs"
        $rusti6 = "\\.\\pipe\\__rust_anonymous_pipe1__."
        $rusti7 = "Local\\RustBacktraceMutex00000000"
        
        $unref = "AppPolicyGetProcessTerminationMethod"

        $susurl = "https://reboot.show/boredape/downloadx.cmdsrc\\main.rs"

        $rusty1 = ".cargo" ascii wide
        $rusty2 = "rust_panic" ascii wide
        $rusty3 = "rustc" ascii wide
        $pattern1 = "C:\\Users\\peter\\OneDrive\\Documents\\Others\\CTHULHU\\target\\release\\deps\\rcrypt.pdb" ascii wide
        $pattern2 = "C:\\Users\\Administrator\\Desktop\\CK-567-master\\CK-567-master\\target\\release\\loader\\target\\release\\deps\\payload.pdb" ascii wide
        $pattern3 = "HELP_RECOVER_ALL_MY_FILES.txt" ascii wide
        $pattern4 = "C:\\Users\\peter\\.cargo" ascii wide
        $pattern5 = "C:\\Users\\runneradmin\\.cargo" ascii wide
        $pattern6 = "C:\\Users\\Administrator\\.cargo" ascii wide
        $pattern7 = "D:\\rust\\icojz\\target\\release\\deps\\mh3242.pdb" ascii wide
        $pattern8 = "conn.ping_pong" ascii wide
        $pattern9 = "\\Device\\Afd\\Mio" ascii wide
        $pattern10 = "D:\\rust\\xinjzq\\target\\release\\deps\\ai360.pdb" ascii wide
        $pattern11 = "uespemosarenegylmodnarodsetybdet" ascii wide
        $pattern12 = "1.3.6.1.5.5.7.3.1" ascii wide
        $pattern13 = "1.3.6.1.4.1.311.10.3.3" ascii wide
        $pattern14 = "C:\\Users\\user\\Documents\\Project\\check_name\\target\\debug\\deps\\FingerPrint_disable_x64.pdb" ascii wide
        $pattern15 = "args.rscmd.exe" ascii wide
        
    condition:
        (6 of ($s*)) or
        ($a_01_0) or
        (4 of ($rusti*) and $unref and $susurl) or 
        (((1 of ($rusty*)) and (2 or all of ($pattern*)))) 
}
