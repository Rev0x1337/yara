rule BootKitty {
	strings:
		//Exe
		
		$exe_dir0 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\SafeStrin" ascii
		$exe_dir1 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\String.c" ascii
		$exe_dir2 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\DivU64x32" ascii
		$exe_dir3 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\LShiftU64" ascii
		$exe_dir4 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\RShiftU64" ascii
		$exe_dir5 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseMemoryLib\\Set" ascii
		$exe_dir6 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseMemoryLib\\Zer" ascii
		$exe_dir7 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseMemoryLib\\Cop" ascii
		$exe_dir8 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseMemoryLib\\Mem" ascii
		$exe_dir9 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BasePrintLib\\Prin" ascii
		$exe_dir10 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiLib\\UefiLibPr" ascii
		$exe_dir11 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiLib\\UefiLib.c" ascii
		$exe_dir12 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiBootServicesT" ascii
		$exe_dir13 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiRuntimeServic" ascii
		$exe_dir14 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiDevicePathLib" ascii
		$exe_dir15 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiDebugLibConOu" ascii
		$exe_dir16 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\UefiMemoryAllocat" ascii
		$exe_dir17 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\Unaligned" ascii
		$exe_dir18 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\DivU64x32" ascii
		$exe_dir19 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdePkg\\Library\\BaseLib\\BitField." ascii
		$exe_dir20 = "D:\\Projects\\Bootkitty-Linux\\edk2\\MdeModulePkg\\Library\\UefiHiiServ" ascii
		$exe_dir21 = "D:\\Projects\\Bootkitty-Linux\\x64\\Release\\BootKit.pdb" ascii
		
		$exe_var_author = {53 00 65 00 63 00 75 00 72 00 65 00 42 00 6F 00 6F 00 74 00 00 00 00 00 42 6F 6F 74 4B 69 74 00 5C 00 45 00 46 00 49 00 5C 00 75 00 62 00 75 00 6E 00 74 00 75 00 5C 00 67 00 72 00 75 00 62 00 78 00 36 00 34 00 2D 00 72 00 65 00 61 00 6C 00 2E 00 65 00 66 00 69 00 00 00 00 00 00 00 00 00 42 00 6F 00 6F 00 74 00 6B 00 69 00 74 00 74 00 79 00 27 00 73 00 20 00 42 00 6F 00 6F 00 74 00 6B 00 69 00 74 00 0A 00 00 00 00 00 00 00 00 00 2D 00 20 00 44 00 65 00 76 00 6C 00 6F 00 70 00 65 00 64 00 20 00 42 00 79 00 20 00 42 00 6C 00 61 00 63 00 6B 00 43 00 61 00 74 00}
		
		$exe_var_irankit = {49 72 61 6E 75 4B 49 54 31}
		$exe_var_bootkit = {42 6F 6F 74 4B 69 74 74 79 31}
		
		$exe_var_inj = "PRELOAD=/opt/injector.so" ascii
		
		$exe_var_banner = {B6 00 31 00 30 00 31 00 31 00 31 00 31 00 00 00 2B 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 2B 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 2C 00 2D 00 2D 00 2D 00 2D 00 2D 00 2E 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 20 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 20 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 7C 00 20 00 20 00 7C 00 29 00 20 00 2F 00 5F 00 20 00 20 00 2C 00 2D 00 2D 00 2D 00 2E 00 20 00 20 00 2C 00 2D 00 2D 00 2D 00 2E 00 20 00 2C 00 2D 00 27 00 20 00 20 00 27 00 2D 00 2E 00 7C 00 20 00 20 00 7C 00 2C 00 2D 00 2E 00 20 00 60 00 2D 00 2D 00 27 00 2C 00 2D 00 27 00 20 00 20 00 27 00 2D 00 2E 00 2C 00 2D 00 27 00 20 00 20 00 27 00 2D 00 2E 00 2C 00 2D 00 2D 00 2E 00 20 00 2C 00 2D 00 2D 00 2E 00 20 00 20 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 7C 00 20 00 20 00 2E 00 2D 00 2E 00 20 00 20 00 5C 00 7C 00 20 00 2E 00 2D 00 2E 00 20 00 7C 00 7C 00 20 00 2E 00 2D 00 2E 00 20 00 7C 00 27 00 2D 00 2E 00 20 00 20 00 2E 00 2D 00 27 00 7C 00 20 00 20 00 20 00 20 00 20 00 2F 00 20 00 2C 00 2D 00 2D 00 2E 00 27 00 2D 00 2E 00 20 00 20 00 2E 00 2D 00 27 00 27 00 2D 00 2E 00 20 00 20 00 2E 00 2D 00 27 00 20 00 5C 00 20 00 20 00 27 00 20 00 20 00 2F 00 20 00 20 00 20 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 7C 00 20 00 20 00 27 00 2D 00 2D 00 27 00 20 00 2F 00 27 00 20 00 27 00 2D 00 27 00 20 00 27 00 27 00 20 00 27 00 2D 00 27 00 20 00 27 00 20 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 5C 00 20 00 20 00 5C 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 20 00 20 00 7C 00 20 00 20 00 7C 00 20 00 20 00 20 00 20 00 5C 00 20 00 20 00 20 00 27 00 20 00 20 00 20 00 20 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 60 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 27 00 20 00 20 00 60 00 2D 00 2D 00 2D 00 27 00 20 00 20 00 60 00 2D 00 2D 00 2D 00 27 00 20 00 20 00 20 00 60 00 2D 00 2D 00 27 00 20 00 20 00 60 00 2D 00 2D 00 27 00 60 00 2D 00 2D 00 27 00 20 00 20 00 60 00 2D 00 2D 00 27 00 20 00 20 00 20 00 20 00 60 00 2D 00 2D 00 27 00 20 00 20 00 2E 00 2D 00 27 00 20 00 20 00 2F 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 60 00 2D 00 2D 00 2D 00 27 00 20 00 20 00 20 00 20 00 20 00 20 00 7C 00 00 00 00 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 3D 00 00 00 00 00}
		
		//Elf
		
		$elf_sbin = "PATH=/sbin:/usr/sbin:/bin:/usr/bin" ascii
		$elf_path1 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader/Utils/hide_features.c" ascii
		$elf_path2 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader/dropper.mod.c" ascii
		$elf_path3 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader" ascii
		$elf_path4 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader/dropper/dropper.c" ascii
		$elf_path5 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader/Utils/create_rootkit.c" ascii
		$elf_path6 = "/home/blackcat/Desktop/workspace/Rootkit/rootkit_loader/Utils" ascii
		$elf_path7 = "/opt/rootkit_loader.ko" ascii
		$elf_bash0 = "/bin/bash" ascii
		$elf_bash1 = "/opt/observer" ascii
		$elf_author = "author=BlackCat" ascii
		$elf_include = "include/linux/thread_info.h" ascii
		$elf_var0 = "observer" ascii
		$elf_var1 = "dropper" nocase ascii
		$elf_var2 = "rootkit" ascii
		$elf_var3 = "injector" nocase ascii
		$elf_var4 = "pidof gdm" ascii
		
	condition:
		filesize < 1MB and (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) 
		and (
		(all of ($exe*)) or
		(10 of ($exe_dir*) and any of ($exe_var*)) or
		(all of ($elf*)) or
		($elf_sbin and 1 of ($elf_path*) and 1 of ($elf_bash*) and $elf_author and 1 of ($elf_var*)) or
		($elf_path7 and $elf_var4)
		
		)
}
