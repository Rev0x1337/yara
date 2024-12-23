rule BitRAT 
{
    strings:
        $tinynuke_paste1 = "TaskbarGlomLevel"
        $tinynuke_paste2 = "profiles.ini"
        $tinynuke_paste3 = "RtlCreateUserThread"
        $tinynuke_paste4 = "127.0.0.1"
        $tinynuke_paste5 = "Shell_TrayWnd"
        $tinynuke_paste6 = "cmd.exe /c start "
        $tinynuke_paste7 = "nss3.dll"
        $tinynuke_paste8 = "IsRelative="
        $tinynuke_paste9 = "-no-remote -profile "
        $tinynuke_paste10 = "AVE_MARIA"
        
        $commandline1 = "-prs" wide
        $commandline2 = "-wdkill" wide
        $commandline3 = "-uac" wide
        $commandline4 = "-fwa" wide
        
        $sequence_0 = { 85c9 753f 6a00 6a00 68c1000000 6809020000 6a28 }
            // n = 7, score = 200
            //   85c9                 | test                ecx, ecx
            //   753f                 | jne                 0x41
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68c1000000           | push                0xc1
            //   6809020000           | push                0x209
            //   6a28                 | push                0x28

        $sequence_1 = { ff7608 ff74241c e8???????? 8be8 83c408 85ed 7425 }
            // n = 7, score = 200
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax
            //   83c408               | add                 esp, 8
            //   85ed                 | test                ebp, ebp
            //   7425                 | je                  0x27

        $sequence_2 = { e8???????? 8be8 83c408 85ed 7930 6a00 6a00 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8be8                 | mov                 ebp, eax
            //   83c408               | add                 esp, 8
            //   85ed                 | test                ebp, ebp
            //   7930                 | jns                 0x32
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_3 = { 8be5 5d c3 8b4510 8320b7 c7400400000000 33c0 }
            // n = 7, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8320b7               | and                 dword ptr [eax], 0xffffffb7
            //   c7400400000000       | mov                 dword ptr [eax + 4], 0
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { e8???????? 83c408 85c0 74cf 894704 8b450c 895f10 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   74cf                 | je                  0xffffffd1
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   895f10               | mov                 dword ptr [edi + 0x10], ebx

        $sequence_5 = { f20f114af8 f20f1142f0 0fbf06 660f6ec8 0fbf46fe 83c608 f30fe6c9 }
            // n = 7, score = 200
            //   f20f114af8           | movsd               qword ptr [edx - 8], xmm1
            //   f20f1142f0           | movsd               qword ptr [edx - 0x10], xmm0
            //   0fbf06               | movsx               eax, word ptr [esi]
            //   660f6ec8             | movd                xmm1, eax
            //   0fbf46fe             | movsx               eax, word ptr [esi - 2]
            //   83c608               | add                 esi, 8
            //   f30fe6c9             | cvtdq2pd            xmm1, xmm1

        $sequence_6 = { f644242401 895c2410 7413 83faff 0f84f5000000 42 89542414 }
            // n = 7, score = 200
            //   f644242401           | test                byte ptr [esp + 0x24], 1
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   7413                 | je                  0x15
            //   83faff               | cmp                 edx, -1
            //   0f84f5000000         | je                  0xfb
            //   42                   | inc                 edx
            //   89542414             | mov                 dword ptr [esp + 0x14], edx

        $sequence_7 = { eb12 6a00 6a00 6a06 6a79 6a2c e8???????? }
            // n = 7, score = 200
            //   eb12                 | jmp                 0x14
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a06                 | push                6
            //   6a79                 | push                0x79
            //   6a2c                 | push                0x2c
            //   e8????????           |                     

        $sequence_8 = { f00fc14108 48 7505 8b01 ff5004 8b4df4 64890d00000000 }
            // n = 7, score = 200
            //   f00fc14108           | lock xadd           dword ptr [ecx + 8], eax
            //   48                   | dec                 eax
            //   7505                 | jne                 7
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_9 = { c70100000000 83c104 83c204 3bce 75e8 8bc2 5e }
            // n = 7, score = 200
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   83c104               | add                 ecx, 4
            //   83c204               | add                 edx, 4
            //   3bce                 | cmp                 ecx, esi
            //   75e8                 | jne                 0xffffffea
            //   8bc2                 | mov                 eax, edx
            //   5e                   | pop                 esi

    
    condition:
        ((8 of ($tinynuke_paste*)) and (3 of ($commandline*))) or
        (7 of them and filesize < 19405824)
}
