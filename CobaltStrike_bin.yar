rule CobaltSrike_bin
{
    strings:
        $payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }
        $decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }
        $pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
        
        $decoderFunc1 = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
        $decoderFunc2  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }
        
        $str1 = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }
        $decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }
        $fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}
		
		$version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 } 
		
		$version_sig1 = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }
		$decode1 = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }
		
		$version_sig3 = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }
        $decode3 = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
        
        $version_sig4 = { 83 F8 12 77 10 FF 24 }
        $decode4 = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }
        
        $version_sig5 = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
        $decode5 = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
        
        $version_sig6 = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
        $decode6 = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }
        
        $version_sig7 = { 83 F8 22 0F 87 96 01 00 00 FF 24 }
        $decode7 = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }
        
        $version_sig8 = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }
        $decode8 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig9 = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }
        $decode9 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig10 = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }
        $decode10 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig11 = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }
        $decode11 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig12 = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }
        $decode12 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig13 = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }
        $decode13 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig14 = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }
        $decode14 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }
        
        $version_sig15 = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }
        $decode15 = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }
        
        $version_sig16 = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }
        $decode16 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig17 = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }
        $decode17 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig18 = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }
        $decode18 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig19 = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }
        $decode19 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig20 = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }
        $decode20 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
        $c2_1 = "ns7.softline.top" xor
        $c2_2 = "ns8.softline.top" xor
        $c2_3 = "ns9.softline.top" xor
        
        $version_sig21 = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }
        $decode21 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig22 = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }
        $decode22 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig23 = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }
        $decode23 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig24 = { 83 FA 5B 77 15 FF 24 }
        $decode24 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig25 = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }
        $decode25 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig26 = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }
        $decode26 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig27 = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }
        $decode27 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig28 = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }
        $decode28 = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
        
        $version_sig29 = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00 EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30 48 83 C4 20 }
        $decode29 = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
                     
        $version_sig30 = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }
        $decode30 = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
        
        $version_sig31 = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF 41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00 48 8B 5C 24 30 48 83 C4 20 }
        $decode31 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }  
         
        $version_sig32 = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 48 8B 5C 24 30 48 83 C4 20 5F }    
        $decode32 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
        
        $version_sig33 = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27 0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14 0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C 0F 87 C8 00 00 00 0F 84 B3 00 00 00 }
        $decode33 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 } 
        
        $version_sig34 = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28 0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15 0F 87 DB 01 00 00 0F 84 BF 01 00 00 } 
        $decode34 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
        
        $version_sig35 = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF E8 8F 55 00 00 }  
        $decode35 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }  
        
        $version_sig36 = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00 0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00 0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00 0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02 0F 84 A6 00 00 00 FF C9 }
        $decode36 = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }
    
       $version_sig37 = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 } 
       $decode37 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig38 = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0 49 8B CA E8 22 55 FF FF }
       $decode38 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 } 
       
       $version_sig39 = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA 48 83 C4 28 }
       $decode39 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig40 = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF 8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0 4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }
       $decode40 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig41 = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00 0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9 0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }
       $decode41 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig42 = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF 4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
       $decode42 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig43 = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF 4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }
       $decode43 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $version_sig44 = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF 8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }
       $decode44 = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
       
       $calls = {
			41 BA C2 DB 37 67
			FF D5
			48 [2]
			48 [2]
			41 BA B7 E9 38 FF
			FF D5
			4D [2]
			48 [2]
			48 [2]
			41 BA 74 EC 3B E1
			FF D5
			48 [2]
			48 [2]
			41 BA 75 6E 4D 61
		}
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		
		$apiLocator1 = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}
		
		$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		$fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"
		
		$socket_recv1 = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}
		
		$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		
		$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}
		$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}
		
		$isHighIntegrityProcess1 = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}
		$executeTaskmgr1 = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}
		
		$deleteFileCOM1 = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}	
		$copyFileCOM1 = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}
		
		$ps1 = "$s=New-Object \x49O.MemoryStream(,[Convert]::\x46romBase64String(" nocase
        $ps2 ="));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" nocase
        
        $dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}
		$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
		$nfp = "npf.sys" nocase
	    $wpcap = "wpcap.dll" nocase
	    
	    $dropComponentsAndActivateDriver_prologue1 = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}
		$dropFile1 = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}
		
		$apiLocator2 = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$dnsapi = { 68 64 6E 73 61 }
		
		$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}
		
		$wnd_proc1 = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}
		
		$apiLocator3 = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$InternetSetOptionA = {
			BA 1F 00 00 00
			6A 00
			68 80 33 00 00
			49 [2]
			41 ?? 04 00 00 00
			41 ?? 75 46 9E 86
		}
		
		$apiLocator4 = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$InternetSetOptionA1 = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}
		
		$apiLocator5 = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}
		
		$apiLocator6 = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}
		
		
		$apiLocator7 = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}	
		$calls1 = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}
		
		$apiLocator8 = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}
		
		$smb = { 68 C6 96 87 52 }	
		$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}
		
		$arch = "platform.architecture()"
        $nope = "WindowsPE"
        $alloc = "ctypes.windll.kernel32.VirtualAlloc"
        $movemem = "ctypes.windll.kernel32.RtlMoveMemory"
        $thread = "ctypes.windll.kernel32.CreateThread"
        $wait = "ctypes.windll.kernel32.WaitForSingleObject"
        
        $scriptletstart = "<scriptlet>" nocase
        $registration = "<registration progid=" nocase
        $classid = "classid=" nocase
		$scriptlang = "<script language=\"vbscript\">" nocase
		$cdata = "<![CDATA["
        $scriptend = "</script>" nocase
	    $antiregistration = "</registration>" nocase
        $scriptletend = "</scriptlet>"
        
        $ea = "Excel.Application" nocase
        $vis = "Visible = False" nocase
        $wsc = "Wscript.Shell" nocase
        $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
        $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
        $regwrite = ".RegWrite" nocase
        $dw = "REG_DWORD"
        $code = ".CodeModule.AddFromString"
        $ao = { 41 75 74 6f 5f 4f 70 65 6e }
        $da = ".DisplayAlerts"
        
        $importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
        $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
        $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
        $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
        $paramsGIM = ".GenerateInMemory = $True" nocase
        $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
        
        $dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
        $imm = "InMemoryModule" nocase
        $mdt = "MyDelegateType" nocase
        $rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
        $data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
        $64bitSpecific = "[IntPtr]::size -eq 8"
        $mandatory = "Mandatory = $True"
        
        $createstuff = "Function CreateStuff Lib \"kernel32\" Alias \"CreateRemoteThread\"" nocase
        $allocstuff = "Function AllocStuff Lib \"kernel32\" Alias \"VirtualAllocEx\"" nocase
        $writestuff = "Function WriteStuff Lib \"kernel32\" Alias \"WriteProcessMemory\"" nocase
        $runstuff = "Function RunStuff Lib \"kernel32\" Alias \"CreateProcessA\"" nocase
        $vars = "Dim rwxpage As Long" nocase
        $res = "RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)"
        $rwxpage = "AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)"
        
        $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
        $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}
        
        $stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
        $stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
        $stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}
        
        $core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }
      
      $core_sig1 = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    } 
    
    
     $core_sig2 = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
     $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
    $core_sig3 = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }
    
    $core_sig4 = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }
    
    $core_sig5 = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }
    
    $core_sig6 = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }
    $deobfuscator1 = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }
    
    $core_sig7 = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }
    condition:
    $payloadDecoder or $decoderFunc or $pushFmtStr or
    $decoderFunc1 or $decoderFunc2 or $str1 or $decoderFunction or $fmtBuilder or
    ($version_sig and $decode) or 
    ($version_sig1 and $decode1) or 
    ($version_sig3 and $decode3) or 
    ($version_sig4 and $decode4) or 
    ($version_sig5 and $decode5) or 
    ($version_sig6 and $decode6) or 
    ($version_sig7 and $decode7) or 
    ($version_sig8 and $decode8) or
    ($version_sig9 and $decode9) or  
    ($version_sig10 and $decode10) or 
    ($version_sig11 and $decode11) or 
    ($version_sig12 and $decode12) or 
    ($version_sig13 and $decode13) or 
    ($version_sig14 and $decode14 and not $version3_1_sig) or 
    ($version_sig15 and $decode15) or 
    ($version_sig16 and $decode16) or 
    ($version_sig17 and $decode17) or 
    ($version_sig18 and $decode18) or 
    ($version_sig19 and $decode19) or 
    ($version_sig20 and $decode20 and not (2 of ($c2_*) or $xmrig_srcpath)) or 
    ($version_sig21 and $decode21) or 
    ($version_sig22 and $decode22) or 
    ($version_sig23 and $decode23) or 
    ($version_sig24 and $decode24) or 
    ($version_sig25 and $decode25) or 
    ($version_sig26 and $decode26) or 
    ($version_sig27 and $decode27) or 
    ($version_sig28 and $decode28) or 
    ($version_sig29 and $decode29) or 
    ($version_sig30 and $decode30) or 
    ($version_sig31 and $decode31) or 
    ($version_sig32 and $decode32) or 
    ($version_sig33 and $decode33) or 
    ($version_sig34 and $decode34) or
    ($version_sig35 and $decode35) or 
    ($version_sig36 and $decode36) or  
    ($version_sig37 and $decode37) or 
    ($version_sig38 and $decode38) or 
    ($version_sig39 and $decode39) or 
    ($version_sig40 and $decode40) or 
    ($version_sig41 and $decode41) or 
    ($version_sig42 and $decode42) or 
    ($version_sig43 and $decode43) or 
    ($version_sig44 and $decode44) or 
    ($apiLocator and $calls) or 
    ($apiLocator1 and $ws2_32 and $listenaccept) or 
    ($socket_recv and $fmt) or 
    ($socket_recv1 and $fmt) or 
    ($deleteFileCOM and $copyFileCOM) or 
    ($isHighIntegrityProcess and $executeTaskmgr) or 
    ($isHighIntegrityProcess1 and $executeTaskmgr1) or 
    ($deleteFileCOM1 and $copyFileCOM1) or 
    ($ps1 and $ps2) or 
    ($dropComponentsAndActivateDriver_prologue and $dropFile and $nfp and $wpcap) or 
    ($dropComponentsAndActivateDriver_prologue1 and $dropFile1 and $nfp and $wpcap) or 
    ($apiLocator2 and $dnsapi) or $wnd_proc or $wnd_proc1 or
    ($apiLocator3 and $InternetSetOptionA) or 
    ($apiLocator4 and $InternetSetOptionA1) or 
    ($apiLocator5 and $postInternetOpenJmp) or 
    ($apiLocator6 and $downloaderLoop) or 
    ($apiLocator7 and $calls1) or 
    ($apiLocator8 and $ws2_32 and $connect) or 
    ($apiLocator8 and $smb and $smbstart) or 
    ($arch and $nope and $alloc and $movemem and $thread and $wait) or 
    ($scriptletstart and $registration and $classid and $scriptlang and $cdata and $scriptend and $antiregistration and $scriptletend and @scriptletstart[1] < @registration[1] and @registration[1] < @classid[1] and @classid[1] < @scriptlang[1] and @scriptlang[1] < @cdata[1]) or 
    ($ea and $vis and $wsc and $regkey1 and $regkey2 and $regwrite and $dw and $code and $ao and $da) or
    ($importVA and $importCT and $importWFSO and $compiler and $params and $paramsSys32 and $paramsGIM and $result) or  
    ($dda and $imm and $mdt and $rd and $data and $64bitSpecific and $mandatory) or 
    ($createstuff and $allocstuff and $writestuff and $runstuff and $vars and $res and $rwxpage and @vars[1] < @res[1] and @allocstuff[1] < @rwxpage[1]) or 
    ($stub52 and $stub56) or ($stub58 and $stub59 and $stub63) or 
    $core_sig or $core_sig1 or ($core_sig2 and $deobfuscator) or 
    ($core_sig3 and not $deobfuscator) or $core_sig4 or $core_sig5 or
    ($core_sig6 and $deobfuscator1) or ($core_sig7 and not $deobfuscator1) 
}
