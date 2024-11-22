rule pdf_script {
	strings:
		$magic = { 25 50 44 46 }
		$action0 = "<</S/Launch/Type/Action/Win<<" nocase ascii
		$action1 = "/Type/Action>>" nocase ascii
		$action2 = "/OpenAction" nocase ascii
		$action3 = "<< /Type /Action" nocase ascii
		$action4 = "/Type /Action" nocase ascii
		$uri = "/S /URI /Type /Action /URI"
		$launch = "/S /Launch /Win" nocase ascii
		$cmd = "(cmd.exe)" nocase ascii
		$ps = "powershell" nocase ascii
		$pscom0 = "DownloadFile" nocase ascii
		$pscom1 = "payload" nocase ascii
		$homepath = "%HOMEPATH%" nocase ascii
		$start0 = "start" nocase ascii
		$start1 = "startxref" nocase ascii
		$js0 = "<</S/JavaScript/JS" nocase ascii
		$js1 = /\/JS \([^)]+?\\/
		$js2 = "/JavaScript" nocase ascii
		$emb0 = "/EmbeddedFiles" nocase ascii
		$emb1 = "/EmbeddedFile" nocase ascii
		$url0 = "https://shapeupfitnessdkk-my.sharepoint.com/:b:/g/personal/michelle_shapeupfitness_dk/Ebd2GDh2N8JErL23JmMNmw8BQA7JVpGiS_C6TGkERpma4A?e=xBbtrV"
		$url1 = "https://ipfs.io/ipfs/QmSyYCjyTMyo1dM2dWBY6ExTmodmU1oSBWTdmEDTLrEenC#http://www.booking.com/"
		$url2 = "https://romacul.com.br/workshop/wp-content/mail.outlookoffice365.com.html"
		$url3 = "https://www.hitplus.fr/2018/click.php?url=https://cutt.ly/seU8MT6t#F8i_bfW"
		$url4 = "https://etehadshipping.com/"
		$url5 = "https://afarm.net/"
		$url6 = "https://portals.checkfedexexp.com"
		$url7 = "https://otcworldmedia.com"
		$url8 = "http://tiny.cc/"
		$url9 = "http://128.199.7.40/"
		$invoc = "%%Invocation:" nocase ascii
		$op0 = "-sOutputFile=" nocase ascii
		$op1 = "-dNumRenderingThreads=" nocase ascii
		$op2 = "-sDEVICE=" nocase ascii
		$op3 = "-dAutoRotatePages=" nocase ascii
		$script0 = "<script" nocase ascii
		$script1 = "</script>" nocase ascii
		$tag0 = "<event" nocase ascii
		$tag1 = "</event>" nocase ascii
		$event0 = "event.target.exportXFAData" nocase ascii
		$event1 = "activity=" nocase ascii
		
 	condition:
		($magic at 0 and (8 of them)) or
		($magic at 0 and ($action0 or $action1 or $action2) and ($cmd or $ps) or ($pscom0 or $pscom1) and ($start0 or $start1) and $launch and $homepath and $js0) or
		($magic at 0 and ($action2 or $action3) and (1 of ($emb*))) or 		
		($magic at 0 and ( 1 of($url*))) or
		($magic at 0 and $action4 and ($js1 or $js2)) or
		($magic at 0 and $invoc and (2 of ($op*))) or
		($magic at 0 and $uri) or
		($magic at 0 and (2 of ($script*)) and ((2 of($event*)) and (2 of ($tag*))))
}
