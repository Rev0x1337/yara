rule mal_sh_pattern {
	  strings:
		  $chmod0 = "chmod 777"
		  $chmod1 = "chmod +x"
		  $wget = "wget"
		  $curl = "curl -O"
		  $a0 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget"
		  $a1 = "cd /tmp"
		
		  $path = "PATH=$PATH:/usr/bin:/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin" 
	  condition:
	    (1 of ($chmod*) and any of ($a*)) or
	    ($path and $curl and any of ($chmod*)) or
	    ($a1 and any of($chmod*) and $wget)

}
