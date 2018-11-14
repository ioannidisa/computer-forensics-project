/*TOOLKIT YARA rules colelcted from https://github.com/Yara-Rules/rules/blob/master/malware/ */


/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Chinese_Hacktools.yar*/

rule mswin_check_lm_group {
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass {
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool {
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" fullword ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid {
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 {
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa {
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast {
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
	strings:
		$s2 = "Invalid password hash: %s" fullword ascii
		$s3 = "-= MySql Hash Cracker =- " fullword ascii
		$s4 = "Usage: %s hash" fullword ascii
		$s5 = "Hash: %08lx%08lx" fullword ascii
		$s6 = "Found pass: " fullword ascii
		$s7 = "Pass not found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools {
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX {
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		score = 50
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs {
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"
	strings:
		$s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
		$s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
		$s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
		$s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
		$s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
		$s12 = "mailto:support@sqldbx.com" fullword ascii
		$s15 = "S.last_login_time \"Last Login\", " fullword ascii
	condition:
		uint16(0) == 0x5a4d and 4 of them
}

rule ms10048_x86 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch {
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute {
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}

rule CookieTools {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
	strings:
		$s0 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s8 = "OnGetPasswordP" fullword ascii
		$s12 = "http://www.chinesehack.org/" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule update_PcInit {
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
		$s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
		$s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib {
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 {
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu {
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii
	condition:
		$s0 at 0 and filesize < 50KB and all of them
}

rule ustrrefadd {
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib {
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
	strings:
		$s2 = "IdtTool.sys" fullword ascii
		$s4 = "Idt Tool bY tMd[CsP]" fullword wide
		$s6 = "\\\\.\\slIdtTool" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 {
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
	strings:
		$s1 = "[*] Token system command" fullword ascii
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s3 = "[*] Add to Administrators success" fullword ascii
		$s4 = "[*] User has been successfully added" fullword ascii
		$s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 {
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version {
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" fullword wide
		$s4 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 {
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv {
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"
	strings:
		$s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
		$s2 = " TSInternetUser " fullword wide
		$s3 = "KvInterlockedCompareExchange" fullword ascii
		$s4 = " WINS/DNS " fullword wide
		$s5 = "winerror=%1" fullword wide
		$s6 = "TermService " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms {
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
	strings:
		$s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
		$s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s5 = "Internet Explorer 1.0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare {
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx {
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
	strings:
		$s0 = "WiNrOOt@126.com" fullword wide
		$s1 = "Dll_LoadEx.EXE" fullword wide
		$s3 = "You Already Loaded This DLL ! :(" fullword ascii
		$s10 = "Dll_LoadEx Microsoft " fullword wide
		$s17 = "Can't Load This Dll ! :(" fullword ascii
		$s18 = "WiNrOOt" fullword wide
		$s20 = " Dll_LoadEx(&A)..." fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report {
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 {
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer {
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule dbexpora {
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"
	strings:
		$s0 = "SELECT A.USER FROM SYS.USER_USERS A " fullword ascii
		$s12 = "OCI 8 - OCIDescriptorFree" fullword ascii
		$s13 = "ORACommand *" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 835KB and all of them
}

rule SQLCracker {
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
	strings:
		$s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug {
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look {
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode {
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
		$s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC {
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
	strings:
		$s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s3 = "post-rcv getsockname failed" fullword ascii
		$s4 = "Failed to execute shell, error = %s" fullword ascii
		$s5 = "UDP listen needs -p arg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking {
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"
	strings:
		$s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
		$s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
		$s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
		$s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
		$s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule HScan_v1_20_oncrpc {
	meta:
		description = "Chinese Hacktool Set - file oncrpc.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"
	strings:
		$s1 = "clnt_raw.c - Fatal header serialization error." fullword ascii
		$s2 = "svctcp_.c - cannot getsockname or listen" fullword ascii
		$s3 = "too many connections (%d), compilation constant FD_SETSIZE was only %d" fullword ascii
		$s4 = "svc_run: - select failed" fullword ascii
		$s5 = "@(#)bindresvport.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 340KB and 4 of them
}

rule hscan_gui {
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s {
	meta:
		description = "Chinese Hacktool Set - file s.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"
	strings:
		$s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
		$s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
		$s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
		$s3 = "explorer.exe http://www.hackdos.com" fullword ascii
		$s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
		$s5 = "Failed to read file or invalid data in file!" fullword ascii
		$s6 = "www.hackdos.com" fullword ascii
		$s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
		$s11 = "The interface of kernel library is invalid!" fullword ascii
		$s12 = "eventvwr" fullword ascii
		$s13 = "Failed to decompress data!" fullword ascii
		$s14 = "NOTEPAD.EXE result.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain {
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " fullword ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" fullword ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys {
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf {
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" fullword wide
		$s3 = "\\DosDevices\\XScanPF" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 {
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 {
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP {
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule CN_Tools_Shiell {
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom {
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" fullword wide
		$s8 = "shell3all.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 {
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER {
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd {
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"
	strings:
		$s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
		$s2 = "PipeCmd.exe" fullword wide
		$s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s4 = "%s\\pipe\\%s%s%d" fullword ascii
		$s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "This is a service executable! Couldn't start directly." fullword ascii
		$s8 = "Connecting to Remote Server ...Failed" fullword ascii
		$s9 = "PIPECMDSRV" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp {
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 65KB and all of them
}

rule Dos_netstat {
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
	strings:
		$s0 = "w03a2409.dll" fullword ascii
		$s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide  /* Goodware String - occured 2 times */
		$s2 = "Administrative Status  = %1!u!" fullword wide  /* Goodware String - occured 2 times */
		$s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide  /* Goodware String - occured 2 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule CN_Tools_xsniff {
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule MSSqlPass {
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert {
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle {
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 {
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc {
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 {
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" fullword wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown {
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk {
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner {
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"
	strings:
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "ADVAPI32.DLL" fullword ascii
		$s4 = "VERSION.DLL" fullword ascii
		$s5 = "WSOCK32.DLL" fullword ascii
		$s6 = "COMCTL32.DLL" fullword ascii
		$s7 = "GDI32.DLL" fullword ascii
		$s8 = "SHELL32.DLL" fullword ascii
		$s9 = "USER32.DLL" fullword ascii
		$s10 = "OLEAUT32.DLL" fullword ascii
		$s11 = "LoadLibraryA" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "VirtualProtect" fullword ascii
		$s14 = "VirtualAlloc" fullword ascii
		$s15 = "VirtualFree" fullword ascii
		$s16 = "ExitProcess" fullword ascii
		$s17 = "RegCloseKey" fullword ascii
		$s18 = "GetFileVersionInfoA" fullword ascii
		$s19 = "ImageList_Add" fullword ascii
		$s20 = "BitBlt" fullword ascii
		$s21 = "ShellExecuteA" fullword ascii
		$s22 = "ActivateKeyboardLayout" fullword ascii
		$s23 = "BBABORT" fullword wide
		$s25 = "BBCANCEL" fullword wide
		$s26 = "BBCLOSE" fullword wide
		$s27 = "BBHELP" fullword wide
		$s28 = "BBIGNORE" fullword wide
		$s29 = "PREVIEWGLYPH" fullword wide
		$s30 = "DLGTEMPLATE" fullword wide
		$s31 = "TABOUTBOX" fullword wide
		$s32 = "TFORM1" fullword wide
		$s33 = "MAINICON" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
	strings:
		$s0 = "\\Device\\devIdtTool" fullword wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
		$s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 {
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx {
	meta:
		description = "Chinese Hacktool Set - file lcx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"
	strings:
		$s0 = "c:\\Users\\careful_snow\\" ascii
		$s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s7 = "[-] There is a error...Create a new connection." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s13 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
		$s17 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way {
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
	strings:
		$s0 = "TTFTPSERVERFRM" fullword wide
		$s1 = "TPORTSCANSETFRM" fullword wide
		$s2 = "TIISSHELLFRM" fullword wide
		$s3 = "TADVSCANSETFRM" fullword wide
		$s4 = "ntwdblib.dll" fullword ascii
		$s5 = "TSNIFFERFRM" fullword wide
		$s6 = "TCRACKSETFRM" fullword wide
		$s7 = "TCRACKFRM" fullword wide
		$s8 = "dbnextrow" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan {
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"
	strings:
		$s2 = "Shanlu Studio" fullword wide
		$s3 = "_AutoAttackMain" fullword ascii
		$s4 = "_frmIpToAddr" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c {
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer {
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
		$s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare {
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport {
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
	strings:
		$s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s3 = "%s - command line port scanner" fullword ascii
		$s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
		$s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s6 = ".\\port.ini" fullword ascii
		$s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "http://www.xfocus.org" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Pc_xai {
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
	strings:
		$s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "%APPDATA%\\" fullword ascii
		$s4 = "---- C.Rufus Security Team ----" fullword wide
		$s5 = "www.snzzkz.com" fullword wide
		$s6 = "%CommonProgramFiles%\\" fullword ascii
		$s7 = "GetRand.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash {
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
	strings:
		$s1 = "<description>IEBars</description>" fullword ascii
		$s2 = "PECompact2" fullword ascii
		$s3 = "Radmin, Remote Administrator" fullword wide
		$s4 = "Radmin 3.0 Hash " fullword wide
		$s5 = "HASH1.0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor {
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 {
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
		$s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release {
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco {
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}
rule x64_KiwiCmd {
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL {
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
	strings:
		/* WIDE: ProductName 1433 */
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		/* WIDE: ProductVersion 1,4,3,3 */
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }
	condition:
		uint16(0) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron {
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
	strings:
		$s1 = "\\Device\\IDTProt" fullword wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "\\??\\slIDTProt" fullword wide
		$s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui {
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
		$s2 = "www.target.com" fullword ascii
		$s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
		$s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
	strings:
		$s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
		$s3 = "%s -h www.target.com -all" fullword ascii
		$s4 = ".\\report\\%s-%s.html" fullword ascii
		$s5 = ".\\log\\Hscan.log" fullword ascii
		$s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
		$s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
		$s8 = ".\\conf\\mysql_pass.dic" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr {
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "-->This exploit gives you a Local System shell " ascii
		$s3 = "wmiprvse.exe" fullword ascii
		$s4 = "Try the first %d time" fullword ascii
		$s5 = "-->Build&&Change By p " ascii
		$s6 = "root\\MicrosoftIISv2" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 {
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"
	strings:
		$x1 = "used pepack!" fullword ascii

		$s1 = "KERNEL32.dll" fullword ascii
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$s5 = "VirtualProtect" fullword ascii
		$s6 = "VirtualAlloc" fullword ascii
		$s7 = "VirtualFree" fullword ascii
		$s8 = "ExitProcess" fullword ascii
	condition:
		uint16(0) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ($s*)
}

rule Dos_NtGod {
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink {
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd {
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"
	strings:
		$s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
		$s6 = "NTcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack {
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
	strings:
		$s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
		$s2 = "Successfully --> username %s password %s " fullword ascii
		$s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s4 = "-a automode  automatic crack the mysql password " fullword ascii
		$s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 {
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v {
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
	strings:
		$s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
		$s3 = "OH,Sry.Too long command." fullword ascii
		$s4 = "Success! Commander." fullword ascii
		$s5 = "Hey,how can racle work without ur command ?" fullword ascii
		$s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan {
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis {
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "program terming" fullword ascii
		$s3 = "WinSta0\\Defau" fullword ascii
		$s4 = "* FROM IIsWebInfo" ascii
		$s5 = "www.icehack." ascii
		$s6 = "wmiprvse.exe" fullword ascii
		$s7 = "Pid: %d" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr {
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate {
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
	strings:
		$s1 = "C:\\TEMP\\" fullword ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice {
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd {
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa {
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" fullword wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule hydra_7_3_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"
	strings:
		$s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
		$s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
		$s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan {
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" fullword ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools {
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
	strings:
		$s1 = "DBN_POST" fullword wide
		$s2 = "LOADER ERROR" fullword ascii
		$s3 = "www.1285.net" fullword wide
		$s4 = "TUPFILEFORM" fullword wide
		$s5 = "DBN_DELETE" fullword wide
		$s6 = "DBINSERT" fullword wide
		$s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner {
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff {
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao {
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." fullword ascii
		$s4 = "\\dhlp\\." fullword ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 {
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "VirtualAlloc" fullword ascii
		$s6 = "VirtualFree" fullword ascii
		$s7 = "VirtualProtect" fullword ascii
		$s8 = "ExitProcess" fullword ascii
		$s9 = "user32.dll" fullword ascii
		$s16 = "MessageBoxA" fullword ascii
		$s10 = "wsprintfA" fullword ascii
		$s11 = "kernel32.dll" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "GetModuleHandleA" fullword ascii
		$s14 = "LoadLibraryA" fullword ascii
		$s15 = "odbc32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher {
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
	strings:
		$s1 = "The target is most likely patched." fullword ascii
		$s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
		$s3 = "[ ] Creating evil window" fullword ascii
		$s4 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui {
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 {
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
	strings:
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[*] Add to Administrators success" fullword ascii
		$s5 = "[*] User has been successfully added" fullword ascii
		$s6 = "[>] ms11-08 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 {
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice {
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "sfUserAppDataRoaming" fullword ascii
		$s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
		$s3 = "delphi32.exe" fullword ascii
		$s4 = "hkeyCurrentUser" fullword ascii
		$s5 = "%s is not a valid IP address." fullword wide
		$s6 = "Citadel hooking error" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui {
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = ".\\log\\Hscan.log" fullword ascii
		$s2 = ".\\report\\%s-%s.html" fullword ascii
		$s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
		$s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
		$s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule kiwi_tools {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
		$s2 = "Benjamin Delpy" fullword ascii
		$s3 = "GlobalSign" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule kiwi_tools_gentil_kiwi {
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "mimikatz" fullword wide
		$s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
		$s3 = "Gentil Kiwi" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Dubrute.yar*/
rule dubrute : bruteforcer toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for DuBrute Bruteforcer"
        in_the_wild = true
        family = "Hackingtool/Bruteforcer"
    
    strings:
        $a = "WBrute"
        $b = "error.txt"
        $c = "good.txt"
        $d = "source.txt"
        $e = "bad.txt"
        $f = "Generator IP@Login;Password"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 

        //check for dubrute specific strings
        $a and $b and $c and $d and $e and $f 
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Gen_powerkatz.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "ad_hoc_network_formed" fullword wide
		$s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s5 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_FinFisher_.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule FinSpy_2
{
    meta:
        description = "FinFisher FinSpy"
	author = "botherder https://github.com/botherder"

    strings:
        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        $skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        $mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        $mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        $versions1 = /(f)inspyv2/ nocase
        $versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or any of ($mouserec*) or $driver or any of ($janedow*) or any of ($versions*) or any of ($bootkit*) or $typo1 or $mssounddx
}

rule FinSpy
{
    meta:
        description = "FinFisher FinSpy"
        author = "AlienVault Labs"

    strings:
        $filter1 = "$password14"
        $filter2 = "$screenrec7"
        $filter3 = "$micrec"
        $filter4 = "$skyperec3"
        $filter5 = "$mouserec2"
        $filter6 = "$driver"
        $filter7 = "$janedow2"
        $filter8 = "$bootkit2"

        $password1 = /\/scomma kbd101\.sys/ wide ascii
        $password2 = /(N)AME,EMAIL CLIENT,EMAIL ADDRESS,SERVER NAME,SERVER TYPE,USERNAME,PASSWORD,PROFILE/ wide ascii
        $password3 = /\/scomma excel2010\.part/ wide ascii
        $password4 = /(A)PPLICATION,PROTOCOL,USERNAME,PASSWORD/ wide ascii
        $password5 = /\/stab MSVCR32\.manifest/ wide ascii
        $password6 = /\/scomma MSN2010\.dll/ wide ascii
        $password7 = /\/scomma Firefox\.base/ wide ascii
        $password8 = /(I)NDEX,URL,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD,FILE,HTTP/ wide ascii
        $password9 = /\/scomma IE7setup\.sys/ wide ascii
        $password10 = /(O)RIGIN URL,ACTION URL,USERNAME FIELD,PASSWORD FIELD,USERNAME,PASSWORD,TIMESTAMP/ wide ascii
        $password11 = /\/scomma office2007\.cab/ wide ascii
        $password12 = /(U)RL,PASSWORD TYPE,USERNAME,PASSWORD,USERNAME FIELD,PASSWORD FIELD/ wide ascii
        $password13 = /\/scomma outlook2007\.dll/ wide ascii
        $password14 = /(F)ILENAME,ENCRYPTION,VERSION,CRC,PASSWORD 1,PASSWORD 2,PASSWORD 3,PATH,SIZE,LAST MODIFICATION DATE,ERROR/ wide ascii

        $screenrec1 = /(s)111o00000000\.dat/ wide ascii
        $screenrec2 = /(t)111o00000000\.dat/ wide ascii
        $screenrec3 = /(f)113o00000000\.dat/ wide ascii
        $screenrec4 = /(w)114o00000000\.dat/ wide ascii
        $screenrec5 = /(u)112Q00000000\.dat/ wide ascii
        $screenrec6 = /(v)112Q00000000\.dat/ wide ascii
        $screenrec7 = /(v)112O00000000\.dat/ wide ascii

        //$keylogger1 = /\<%s UTC %s\|%d\|%s\>/ wide ascii
        //$keylogger2 = /1201[0-9A-F]{8}\.dat/ wide ascii

        $micrec = /2101[0-9A-F]{8}\.dat/ wide ascii

        $skyperec1 = /\[%19s\] %25s\:    %s/ wide ascii
        $skyperec2 = /Global\\\{A48F1A32\-A340\-11D0\-BC6B\-00A0C903%\.04X\}/ wide
        //$skyperec3 = /(1411|1421|1431|1451)[0-9A-F]{8}\.dat/ wide ascii

        //$mouserec1 = /(m)sc183Q000\.dat/ wide ascii
        //$mouserec2 = /2201[0-9A-F]{8}\.dat/ wide ascii

        $driver = /\\\\\\\\\.\\\\driverw/ wide ascii

        $janedow1 = /(J)ane Dow\'s x32 machine/ wide ascii
        $janedow2 = /(J)ane Dow\'s x64 machine/ wide ascii

        //$versions1 = /(f)inspyv2/ nocase
        //$versions2 = /(f)inspyv4/ nocase

        $bootkit1 = /(b)ootkit_x32driver/
        $bootkit2 = /(b)ootkit_x64driver/

        $typo1 = /(S)creenShort Recording/ wide

        $mssounddx = /(S)ystem\\CurrentControlSet\\Services\\mssounddx/ wide

    condition:
        (8 of ($password*) or any of ($screenrec*) or $micrec or any of ($skyperec*) or $driver or any of ($janedow*) or any of ($bootkit*) or $typo1 or $mssounddx) and not any of ($filter*)
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Mandibule.yar*/
/* 		Yara rule to detect ELF Linux process injector toolkit "mandibule" generic.
   		name: TOOLKIT_Mandibule.yar analyzed by unixfreaxjp. 
		result:
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-stripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dynx86-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dun64-UNstripped
		TOOLKIT_Mandibule ./mandibule//mandibule-dyn64-stripped

   		This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
   		and  open to any user or organization, as long as you use it under this license.
*/

private rule is__str_mandibule_gen1 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$str01 = "shared arguments too big" fullword nocase wide ascii
		$str02 = "self inject pid: %" fullword nocase wide ascii
		$str03 = "injected shellcode at 0x%lx" fullword nocase wide ascii        	
		$str04 = "target pid: %d" fullword nocase wide ascii        	
		$str05 = "mapping '%s' into memory at 0x%lx" fullword nocase wide ascii
		$str06 = "shellcode injection addr: 0x%lx" fullword nocase wide ascii
		$str07 = "loading elf at: 0x%llx" fullword nocase wide ascii
	condition:
                4 of them
}

private rule is__hex_top_mandibule64 {
	meta:
		author = "unixfreaxjp"
		date = "2018-05-31"
	strings:
		$hex01 = { 48 8D 05 43 01 00 00 48 89 E7 FF D0 } // st
		$hex02 = { 53 48 83 EC 50 48 89 7C 24 08 48 8B 44 24 08 } // mn
		$hex03 = { 48 81 EC 18 02 00 00 89 7C 24 1C 48 89 74 } // pt
		$hex04 = { 53 48 81 EC 70 01 01 00 48 89 7C 24 08 48 8D 44 24 20 48 05 00 00 } // ld
	condition:
                3 of them 
}

private rule is__hex_mid_mandibule32 {
	meta:
		author = "unixfreaxjp"
		date = "2018-06-01"
	strings:
		$hex05 = { E8 09 07 00 00 81 C1 FC 1F 00 00 8D 81 26 E1 FF FF } // st
		$hex06 = { 56 53 83 EC 24 E8 E1 05 00 00 81 C3 D0 1E 00 00 8B 44 24 30} // mn
		$hex07 = { 81 C3 E8 29 00 00 C7 44 24 0C } // pt
		$hex08 = { E8 C6 D5 FF FF 83 C4 0C 68 00 01 00 00 } // ld
	condition:
                3 of them 
}

rule TOOLKIT_Mandibule {
	meta:
		description = "Generic detection for ELF Linux process injector mandibule generic"
		reference = "https://imgur.com/a/MuHSZtC"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-06-01"
	condition:
		((is__str_mandibule_gen1) or (is__hex_mid_mandibule32))
		or ((is__str_mandibule_gen1) or (is__hex_top_mandibule64))
		and is__elf
		and filesize < 30KB 
}
/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_PassTheHash.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule whosthere_alt : Toolkit {
	meta:
		description = "Auto-generated rule - file whosthere-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
	strings:
		$s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '49.00' */
		$s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s2 = "dump output to a file, -o filename" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii /* PEStudio Blacklist: strings */ /* score: '29.00' */
		$s4 = "Error: pth.dll is not in the current directory!." fullword ascii /* score: '24.00' */
		$s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s6 = ".\\pth.dll" fullword ascii /* score: '16.00' */
		$s7 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and 2 of them
}

rule iam_alt_iam_alt : Toolkit  {
	meta:
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00' */
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00' */
		$s3 = "username:domainname:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s4 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii /* score: '12.00' */
		$s6 = "nthash is too long!." fullword ascii /* score: '8.00' */
		$s7 = "LSASS HANDLE: %x" fullword ascii /* score: '5.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule genhash_genhash : Toolkit  {
	meta:
		description = "Auto-generated rule - file genhash.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
	strings:
		$s1 = "genhash.exe <password>" fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s3 = "Password: %s" fullword ascii /* PEStudio Blacklist: strings */ /* score: '17.00' */
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii /* score: '11.00' */
		$s5 = "This tool generates LM and NT hashes." fullword ascii /* score: '10.00' */
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii /* score: '10.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule iam_iamdll : Toolkit  {
	meta:
		description = "Auto-generated rule - file iamdll.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
	strings:
		$s0 = "LSASRV.DLL" fullword ascii /* score: '21.00' */
		$s1 = "iamdll.dll" fullword ascii /* score: '21.00' */
		$s2 = "ChangeCreds" fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule iam_iam : Toolkit  {
	meta:
		description = "Auto-generated rule - file iam.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
	strings:
		$s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
		$s2 = "iam.exe -h administrator:mydomain:"  ascii /* PEStudio Blacklist: strings */ /* score: '40.00' */
		$s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00' */
		$s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
		$s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii /* score: '26.00' */
		$s6 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
		$s7 = "Checking LSASRV.DLL...." fullword ascii /* score: '12.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule whosthere_alt_pth : Toolkit  {
	meta:
		description = "Auto-generated rule - file pth.dll"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
	strings:
		$s0 = "c:\\debug.txt" fullword ascii /* PEStudio Blacklist: strings */ /* score: '23.00' */
		$s1 = "pth.dll" fullword ascii /* score: '20.00' */
		$s2 = "\"Primary\" string found at %.8Xh" fullword ascii /* score: '7.00' */
		$s3 = "\"Primary\" string not found!" fullword ascii /* score: '6.00' */
		$s4 = "segment 1 found at %.8Xh" fullword ascii /* score: '6.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 4 of them
}

rule whosthere : Toolkit  {
	meta:
		description = "Auto-generated rule - file whosthere.exe"
		author = "Florian Roth"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		date = "2015-07-10"
		score = 80
		hash = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
	strings:
		$s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '48.00' */
		$s2 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii /* PEStudio Blacklist: strings */ /* score: '36.00' */
		$s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii /* PEStudio Blacklist: strings */ /* score: '28.00' */
		$s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii /* PEStudio Blacklist: strings */ /* score: '27.00' */
		$s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
		$s6 = "Cannot get LSASS.EXE PID!" fullword ascii /* score: '14.00' */
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and 2 of them
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Powerstager.yar*/
rule Powerstager
{
    meta:
      author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
      date = "02JAN2018"
      hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa" //x86
      hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5" //x64
      description = "Detects PowerStager Windows executable, both x86 and x64"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/"
      reference2 = "https://github.com/z0noxz/powerstager"
    
    strings:
      $filename = /%s\\[a-zA-Z0-9]{12}/
      $pathname = "TEMP" wide ascii
//    $errormsg = "The version of this file is not compatible with the version of Windows you're running." wide ascii
      $filedesc = "Lorem ipsum dolor sit amet, consecteteur adipiscing elit" wide ascii
      $apicall_01 = "memset"
      $apicall_02 = "getenv"
      $apicall_03 = "fopen"
      $apicall_04 = "memcpy"
      $apicall_05 = "fwrite"
      $apicall_06 = "fclose"
      $apicall_07 = "CreateProcessA"
      $decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }
      $decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }
      $decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }
      $decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }

    condition:
      uint16be(0) == 0x4D5A
        and
      all of ($apicall_*)
        and
      $filename
        and
      $pathname
        and
      $filedesc
        and
      (2 of ($decoder_x86*) or 2 of ($decoder_x64*))
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Pwdump.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule QuarksPwDump_Gen : Toolkit  {
	meta:
		description = "Detects all QuarksPWDump versions"
		author = "Florian Roth"
		date = "2015-09-29"
		score = 80
		hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
		hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
		hash4 = "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
		hash5 = "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
		hash6 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
		hash7 = "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
	strings:
		$s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
		$s2 = "%d dumped" fullword ascii
		$s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
		$s4 = "\\SAM-%u.dmp" fullword ascii
	condition:
		all of them
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_THOR_HackTools.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*

   THOR APT Scanner - Hack Tool Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner.

   We will frequently update this file with new rules rated TLP:WHITE

   Florian Roth
   BSK Consulting GmbH
   Web: bsk-consulting.de

   revision: 20150510

   License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
	Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/

/* WCE */

rule WindowsCredentialEditor
{
    meta:
    	description = "Windows Credential Editor" threat_level = 10 score = 90
    strings:
		$a = "extract the TGT session key"
		$b = "Windows Credentials Editor"
    condition:
    	$a or $b
}

rule Amplia_Security_Tool
{
    meta:
		description = "Amplia Security Tool"
		score = 60
		nodeepdive = 1
    strings:
		$a = "Amplia Security"
		$b = "Hernan Ochoa"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"
    condition: 1 of them
}

/* pwdump/fgdump */

rule PwDump
{
	meta:
		description = "PwDump 6 variant"
		author = "Marc Stroebel"
		date = "2014-04-24"
		score = 70
	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
	condition:
		all of them
}

rule PScan_Portscan_1 {
	meta:
		description = "PScan - Port Scanner"
		author = "F. Roth"
		score = 50
	strings:
		$a = "00050;0F0M0X0a0v0}0"
		$b = "vwgvwgvP76"
		$c = "Pr0PhOFyP"
	condition:
		all of them
}

rule HackTool_Samples {
	meta:
		description = "Hacktool"
		score = 50
	strings:
		$a = "Unable to uninstall the fgexec service"
		$b = "Unable to set socket to sniff"
		$c = "Failed to load SAM functions"
		$d = "Dump system passwords"
		$e = "Error opening sam hive or not valid file"
		$f = "Couldn't find LSASS pid"
		$g = "samdump.dll"
		$h = "WPEPRO SEND PACKET"
		$i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
		$j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
		$k = "arpspoof\\Debug"
		$l = "Success: The log has been cleared"
		$m = "clearlogs [\\\\computername"
		$n = "DumpUsers 1."
		$o = "dictionary attack with specified dictionary file"
		$p = "by Objectif Securite"
		$q = "objectif-securite"
		$r = "Cannot query LSA Secret on remote host"
		$s = "Cannot write to process memory on remote host"
		$t = "Cannot start PWDumpX service on host"
		$u = "usage: %s <system hive> <security hive>"
		$v = "username:domainname:LMhash:NThash"
		$w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
		$x = "Impersonation Tokens Available"
		$y = "failed to parse pwdump format string"
		$z = "Dumping password"
	condition:
		1 of them
}

/* Disclosed hack tool set */

rule Fierce2
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Fierce2 domain scanner"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
	condition:
		1 of them
}

rule Ncrack
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Ncrack brute force tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
	condition:
		1 of them
}

rule SQLMap
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "except SqlmapBaseException, ex:"
	condition:
		1 of them
}

rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"
	condition:
		all of them
}

rule DomainScanV1_0 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}

rule MooreR_Port_Scanner {
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"
	condition:
		all of them
}

rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"
	condition:
		all of them
}

rule FeliksPack3___Scanners_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"
	condition:
		all of them
}

rule CGISscan_CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"
	condition:
		all of ($s*)
}

rule IP_Stealing_Utilities {
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"
	condition:
		all of them
}

rule SuperScan4 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s2 = " td class=\"summO1\">"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
	condition:
		all of them

}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s4 = "Start/Stop Portscanning"
		$s6 = "Auto Save LogFile by pressing STOP"
	condition:
		all of them
}

rule scanarator {
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
	condition:
		all of them
}

rule aolipsniffer {
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
	condition:
		all of them
}

rule _Bitchin_Threads_ {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"
	condition:
		all of them
}

rule cgis4_cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"
	condition:
		all of them
}

rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."
	condition:
		all of them
}

rule ProPort_zip_Folder_ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"
	condition:
		all of them
}

rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"
	condition:
		all of them
}

rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
	condition:
		all of them
}

rule scanarator_iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"
	condition:
		all of them
}

rule stealth_Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "This tool may be used only by system administrators. I am not responsible for "
	condition:
		all of them
}

rule Angry_IP_Scanner_v2_08_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"
	condition:
		all of them
}

rule crack_Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"
	condition:
		all of them
}

rule CN_GUI_Scanner {
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		author = "Florian Roth"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		score = 65
		date = "04.10.2014"
	strings:
		$s1 = "good.txt" fullword ascii
		$s2 = "IP.txt" fullword ascii
		$s3 = "xiaoyuer" fullword ascii
		$s0w = "ssh(" fullword wide
		$s1w = ").exe" fullword wide
	condition:
		all of them
}

rule CN_Packed_Scanner {
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii
	condition:
		all of them and filesize < 180KB and filesize > 70KB
}

rule Tiny_Network_Tool_Generic {
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		author = "Florian Roth"
		date = "08.10.2014"
		score = 40
		type = "file"
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
	strings:
		$magic	= { 4d 5a }

		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii

		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii

		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii

		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		( $magic at 0 ) and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*) ) and filesize < 15KB
}

rule Beastdoor_Backdoor {
	meta:
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth"
		score = 55
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword
	condition:
		2 of them
}

rule Powershell_Netcat {
	meta:
		description = "Detects a Powershell version of the Netcat network hacking tool"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
	strings:
		$s0 = "[ValidateRange(1, 65535)]" fullword
		$s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
		$s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
	condition:
		all of them
}

rule Chinese_Hacktool_1014 {
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktool_BAT_PortsOpen {
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
		$s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
		$s2 = "@echo off" ascii
	condition:
		all of them
}

rule CN_Hacktool_SSPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "Golden Fox" fullword wide
		$s1 = "Syn Scan Port" fullword wide
		$s2 = "CZ88.NET" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_ScanPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "LScanPort" fullword wide
		$s1 = "LScanPort Microsoft" fullword wide
		$s2 = "www.yupsoft.com" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_S_EXE_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "\\Result.txt" fullword ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_MilkT_BAT {
	meta:
		description = "Detects a chinese Portscanner named MilkT - shipped BAT"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" ascii
		$s1 = "if not \"%Choice%\"==\"\" set Choice=%Choice:~0,1%" ascii
	condition:
		all of them
}

rule CN_Hacktool_MilkT_Scanner {
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword
	condition:
		all of them
}

rule CN_Hacktool_1433_Scanner {
	meta:
		description = "Detects a chinese MSSQL scanner"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "del Weak1.txt" ascii fullword
		$s3 = "del Attack.txt" ascii fullword
		$s4 = "del /s /Q C:\\Windows\\system32\\doors\\" fullword ascii
		$s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule CN_Hacktool_1433_Scanner_Comp2 {
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$magic = { 4d 5a }
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
	condition:
		( $magic at 0 ) and all of ($s*)
}

rule WCE_Modified_1_1014 {
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		author = "Florian Roth"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		score = 70
	strings:
		$s0 = "LSASS.EXE" fullword ascii
		$s1 = "_CREDS" ascii
		$s9 = "Using WCE " ascii
	condition:
		all of them
}

rule ReactOS_cmd_valid {
	meta:
		description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 30
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
	strings:
		$s1 = "ReactOS Command Processor" fullword wide
		$s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
		$s3 = "Eric Kohl and others" fullword wide
		$s4 = "ReactOS Operating System" fullword wide
	condition:
		all of ($s*)
}

rule iKAT_wmi_rundll {
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "Error!" fullword ascii
		$s2 = "Win32 only!" fullword ascii
		$s3 = "COMCTL32.dll" fullword ascii
		$s4 = "[LordPE]" ascii
		$s5 = "CRTDLL.dll" fullword ascii
		$s6 = "VBScript" fullword ascii
		$s7 = "CoUninitialize" fullword ascii
	condition:
		all of them and filesize < 15KB
}

rule iKAT_revelations {
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
	strings:
		$s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
		$s8 = "BETAsupport@snadboy.com" fullword wide
		$s9 = "support@snadboy.com" fullword wide
		$s14 = "RevelationHelper.dll" fullword ascii
	condition:
		all of them
}

rule iKAT_priv_esc_tasksch {
	meta:
		description = "Task Schedulder Local Exploit - Windows local priv-esc using Task Scheduler, published by webDevil. Supports Windows 7 and Vista."
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "84ab94bff7abf10ffe4446ff280f071f9702cf8b"
	strings:
		$s0 = "objShell.Run \"schtasks /change /TN wDw00t /disable\",,True" fullword ascii
		$s3 = "objShell.Run \"schtasks /run /TN wDw00t\",,True" fullword ascii
		$s4 = "'objShell.Run \"cmd /c copy C:\\windows\\system32\\tasks\\wDw00t .\",,True" fullword ascii
		$s6 = "a.WriteLine (\"schtasks /delete /f /TN wDw00t\")" fullword ascii
		$s7 = "a.WriteLine (\"net user /add ikat ikat\")" fullword ascii
		$s8 = "a.WriteLine (\"cmd.exe\")" fullword ascii
		$s9 = "strFileName=\"C:\\windows\\system32\\tasks\\wDw00t\"" fullword ascii
		$s10 = "For n = 1 To (Len (hexXML) - 1) step 2" fullword ascii
		$s13 = "output.writeline \" Should work on Vista/Win7/2008 x86/x64\"" fullword ascii
		$s11 = "Set objExecObject = objShell.Exec(\"cmd /c schtasks /query /XML /TN wDw00t\")" fullword ascii
		$s12 = "objShell.Run \"schtasks /create /TN wDw00t /sc monthly /tr \"\"\"+biatchFile+\"" ascii
		$s14 = "a.WriteLine (\"net localgroup administrators /add v4l\")" fullword ascii
		$s20 = "Set ts = fso.createtextfile (\"wDw00t.xml\")" fullword ascii
	condition:
		2 of them
}

rule iKAT_command_lines_agent {
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii
	condition:
		4 of them
}

rule iKAT_cmd_as_dll {
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide

		$ext = "extension: .dll" nocase
	condition:
		all of ($s*) and $ext
}

rule iKAT_tools_nmap {
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
	strings:
		$s0 = "Insecure.Org" fullword wide
		$s1 = "Copyright (c) Insecure.Com" fullword wide
		$s2 = "nmap" fullword nocase
		$s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii
	condition:
		all of them
}

rule iKAT_startbar {
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii
	condition:
		all of them
}

rule iKAT_gpdisable_customcmd_kitrap0d_uacpoc {
	meta:
		description = "iKAT hack tool set generic rule - from files gpdisable.exe, customcmd.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "2725690954c2ad61f5443eb9eec5bd16ab320014"
		hash2 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash3 = "b65a460d015fd94830d55e8eeaf6222321e12349"
		score = 20
	strings:
		$s0 = "Failed to get temp file for source AES decryption" fullword
		$s5 = "Failed to get encryption header for pwd-protect" fullword
		$s17 = "Failed to get filetime" fullword
		$s20 = "Failed to delete temp file for password decoding (3)" fullword
	condition:
		all of them
}

rule iKAT_Tool_Generic {
	meta:
		description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 55
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
	strings:
		$s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword
		$s1 = "Failed to read the entire file" fullword
		$s4 = "<VersionCreatedBy>14.4.0</VersionCreatedBy>" fullword
		$s8 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</P"
		$s9 = "Running Zip pipeline..." fullword
		$s10 = "<FinTitle />" fullword
		$s12 = "<AutoTemp>0</AutoTemp>" fullword
		$s14 = "<DefaultDir>%TEMP%</DefaultDir>" fullword
		$s15 = "AES Encrypting..." fullword
		$s20 = "<UnzipDir>%TEMP%</UnzipDir>" fullword
	condition:
		all of them
}

rule BypassUac2 {
	meta:
		description = "Auto-generated rule - file BypassUac2.zip"
		author = "yarGen Yara Rule Generator"
		hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
	strings:
		$s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
		$s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
		$s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
	condition:
		all of them
}

rule BypassUac_3 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "yarGen Yara Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide
	condition:
		3 of them
}

rule BypassUac_9 {
	meta:
		description = "Auto-generated rule - file BypassUac.zip"
		author = "yarGen Yara Rule Generator"
		hash = "93c2375b2e4f75fc780553600fbdfd3cb344e69d"
	strings:
		$s0 = "/x86/BypassUac.exe" fullword ascii
		$s1 = "/x64/BypassUac.exe" fullword ascii
		$s2 = "/x86/BypassUacDll.dll" fullword ascii
		$s3 = "/x64/BypassUacDll.dll" fullword ascii
		$s15 = "BypassUac" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_6 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUacDll_7 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s3 = "BypassUacDLL.dll" fullword wide
		$s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
	condition:
		all of them
}

rule BypassUac_EXE {
	meta:
		description = "Auto-generated rule - file BypassUacDll.aps"
		author = "yarGen Yara Rule Generator"
		hash = "58d7b24b6870cb7f1ec4807d2f77dd984077e531"
	strings:
		$s1 = "Wole32.dll" wide
		$s3 = "System32\\migwiz" wide
		$s4 = "System32\\migwiz\\CRYPTBASE.dll" wide
		$s5 = "Elevation:Administrator!new:" wide
		$s6 = "BypassUac" wide
	condition:
		all of them
}

rule APT_Proxy_Malware_Packed_dev
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
	strings:
		$string0 = "PECompact2" fullword
		$string1 = "[LordPE]"
		$string2 = "steam_ker.dll"
	condition:
		all of them
}

rule Tzddos_DDoS_Tool_CN {
	meta:
		description = "Disclosed hacktool set - file tzddos"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
		$s6 = "del Result.txt s2.txt s1.txt " fullword ascii
	condition:
		all of them
}

rule Ncat_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
	strings:
		$s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
		$s3 = "gethostpoop fuxored" fullword ascii
		$s6 = "VERNOTSUPPORTED" fullword ascii
		$s7 = "%s [%s] %d (%s)" fullword ascii
		$s12 = " `--%s' doesn't allow an argument" fullword ascii
	condition:
		all of them
}

rule MS08_067_Exploit_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file cs.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a3e9e0655447494253a1a60dbc763d9661181322"
	strings:
		$s0 = "MS08-067 Exploit for CN by EMM@ph4nt0m.org" fullword ascii
		$s3 = "Make SMB Connection error:%d" fullword ascii
		$s5 = "Send Payload Over!" fullword ascii
		$s7 = "Maybe Patched!" fullword ascii
		$s8 = "RpcExceptionCode() = %u" fullword ascii
		$s11 = "ph4nt0m" fullword wide
		$s12 = "\\\\%s\\IPC" ascii
	condition:
		4 of them
}

rule Hacktools_CN_Burst_sql {
	meta:
		description = "Disclosed hacktool set - file sql.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d5139b865e99b7a276af7ae11b14096adb928245"
	strings:
		$s0 = "s.exe %s %s %s %s %d /save" fullword ascii
		$s2 = "s.exe start error...%d" fullword ascii
		$s4 = "EXEC sp_addextendedproc xp_cmdshell,'xplog70.dll'" fullword ascii
		$s7 = "EXEC master..xp_cmdshell 'wscript.exe cc.js'" fullword ascii
		$s10 = "Result.txt" fullword ascii
		$s11 = "Usage:sql.exe [options]" fullword ascii
		$s17 = "%s root %s %d error" fullword ascii
		$s18 = "Pass.txt" fullword ascii
		$s20 = "SELECT sillyr_at_gmail_dot_com INTO DUMPFILE '%s\\\\sillyr_x.so' FROM sillyr_x" fullword ascii
	condition:
		6 of them
}

rule Hacktools_CN_Panda_445TOOL {
	meta:
		description = "Disclosed hacktool set - file 445TOOL.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "92050ba43029f914696289598cf3b18e34457a11"
	strings:
		$s0 = "scan.bat" fullword ascii
		$s1 = "Http.exe" fullword ascii
		$s2 = "GOGOGO.bat" fullword ascii
		$s3 = "ip.txt" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Panda_445 {
	meta:
		description = "Disclosed hacktool set - file 445.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a61316578bcbde66f39d88e7fc113c134b5b966b"
	strings:
		$s0 = "for /f %%i in (ips.txt) do (start cmd.bat %%i)" fullword ascii
		$s1 = "445\\nc.exe" fullword ascii
		$s2 = "445\\s.exe" fullword ascii
		$s3 = "cs.exe %1" fullword ascii
		$s4 = "445\\cs.exe" fullword ascii
		$s5 = "445\\ip.txt" fullword ascii
		$s6 = "445\\cmd.bat" fullword ascii
		$s9 = "@echo off" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_WinEggDrop {
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
	strings:
		$s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
		$s8 = "Something Wrong About The Ports" fullword ascii
		$s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
		$s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
		$s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
		$s13 = "%-16s %-5d -> \"%s\"" fullword ascii
		$s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
		$s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
		$s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Scan_BAT {
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_Burst {
	meta:
		description = "Disclosed hacktool set - file Burst.rar"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii
	condition:
		all of them
}

rule Hacktools_CN_445_cmd {
	meta:
		description = "Disclosed hacktool set - file cmd.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "69b105a3aec3234819868c1a913772c40c6b727a"
	strings:
		$bat = "@echo off" fullword ascii
		$s0 = "cs.exe %1" fullword ascii
		$s2 = "nc %1 4444" fullword ascii
	condition:
		$bat at 0 and all of ($s*)
}

rule Hacktools_CN_GOGOGO_Bat {
	meta:
		description = "Disclosed hacktool set - file GOGOGO.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "4bd4f5b070acf7fe70460d7eefb3623366074bbd"
	strings:
		$s0 = "for /f \"delims=\" %%x in (endend.txt) do call :lisoob %%x" fullword ascii
		$s1 = "http://www.tzddos.com/ -------------------------------------------->byebye.txt" fullword ascii
		$s2 = "ren %systemroot%\\system32\\drivers\\tcpip.sys tcpip.sys.bak" fullword ascii
		$s4 = "IF /I \"%wangle%\"==\"\" ( goto start ) else ( goto erromm )" fullword ascii
		$s5 = "copy *.tzddos scan.bat&del *.tzddos" fullword ascii
		$s6 = "del /f tcpip.sys" fullword ascii
		$s9 = "if /i \"%CB%\"==\"www.tzddos.com\" ( goto mmbat ) else ( goto wangle )" fullword ascii
		$s10 = "call scan.bat" fullword ascii
		$s12 = "IF /I \"%erromm%\"==\"\" ( goto start ) else ( goto zuihoujh )" fullword ascii
		$s13 = "IF /I \"%zuihoujh%\"==\"\" ( goto start ) else ( goto laji )" fullword ascii
		$s18 = "sc config LmHosts start= auto" fullword ascii
		$s19 = "copy tcpip.sys %systemroot%\\system32\\drivers\\tcpip.sys > nul" fullword ascii
		$s20 = "ren %systemroot%\\system32\\dllcache\\tcpip.sys tcpip.sys.bak" fullword ascii
	condition:
		3 of them
}

rule Hacktools_CN_Burst_pass {
	meta:
		description = "Disclosed hacktool set - file pass.txt"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "55a05cf93dbd274355d798534be471dff26803f9"
	strings:
		$s0 = "123456.com" fullword ascii
		$s1 = "123123.com" fullword ascii
		$s2 = "360.com" fullword ascii
		$s3 = "123.com" fullword ascii
		$s4 = "juso.com" fullword ascii
		$s5 = "sina.com" fullword ascii
		$s7 = "changeme" fullword ascii
		$s8 = "master" fullword ascii
		$s9 = "google.com" fullword ascii
		$s10 = "chinanet" fullword ascii
		$s12 = "lionking" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_JoHor_Posts_Killer {
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
	strings:
		$s0 = "Multithreading Posts_Send Killer" fullword ascii
		$s3 = "GET [Access Point] HTTP/1.1" fullword ascii
		$s6 = "The program's need files was not exist!" fullword ascii
		$s7 = "JoHor_Posts_Killer" fullword wide
		$s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$s10 = "  ( /s ) :" fullword ascii
		$s11 = "forms.vbp" fullword ascii
		$s12 = "forms.vcp" fullword ascii
		$s13 = "Software\\FlySky\\E\\Install" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tesksd {
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
	strings:
		$s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
		$s1 = "ExeMiniDownload.exe" fullword wide
		$s16 = "POST %Hs" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Http {
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii
	condition:
		all of them and filesize < 10KB
}

rule Hacktools_CN_Burst_Start {
	meta:
		description = "Disclosed hacktool set - file Start.bat - DoS tool"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "75d194d53ccc37a68286d246f2a84af6b070e30c"
	strings:
		$s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" fullword ascii
		$s1 = "Blast.bat /r 600" fullword ascii
		$s2 = "Blast.bat /l Blast.bat" fullword ascii
		$s3 = "Blast.bat /c 600" fullword ascii
		$s4 = "start Clear.bat" fullword ascii
		$s5 = "del Result.txt" fullword ascii
		$s6 = "s syn %%i %%j 3306 /save" fullword ascii
		$s7 = "start Thecard.bat" fullword ascii
		$s10 = "setlocal enabledelayedexpansion" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tasksvr {
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii
	condition:
		all of them
}
rule Hacktools_CN_Burst_Clear {
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
	strings:
		$s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
		$s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
		$s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
		$s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
		$s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
		$s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
		$s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
		$s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
		$s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii
	condition:
		5 of them
}

rule Hacktools_CN_Burst_Thecard {
	meta:
		description = "Disclosed hacktool set - file Thecard.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "50b01ea0bfa5ded855b19b024d39a3d632bacb4c"
	strings:
		$s0 = "tasklist |find \"Clear.bat\"||start Clear.bat" fullword ascii
		$s1 = "Http://www.coffeewl.com" fullword ascii
		$s2 = "ping -n 2 localhost 1>nul 2>nul" fullword ascii
		$s3 = "for /L %%a in (" fullword ascii
		$s4 = "MODE con: COLS=42 lines=5" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Burst_Blast {
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
		$s1 = "@echo off" fullword ascii
	condition:
		all of them
}

rule VUBrute_VUBrute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii
	condition:
		all of them
}

rule DK_Brute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii
	condition:
		all of them
}

rule VUBrute_config {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii
	condition:
		all of them
}

rule sig_238_hunt {
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
	strings:
		$s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
		$s3 = "Usage - hunt \\\\servername" fullword ascii
		$s4 = ".share = %S - %S" fullword wide
		$s5 = "SMB share enumerator and admin finder " fullword ascii
		$s7 = "Hunt only runs on Windows NT..." fullword ascii
		$s8 = "User = %S" fullword ascii
		$s9 = "Admin is %s\\%s" fullword ascii
	condition:
		all of them
}

rule sig_238_listip {
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
	strings:
		$s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
		$s2 = "ERROR No.2!!! Program Terminate." fullword ascii
		$s4 = "Local Host Name: %s" fullword ascii
		$s5 = "Packed by exe32pack 1.38" fullword ascii
		$s7 = "Local Computer Name: %s" fullword ascii
		$s8 = "Local IP Adress: %s" fullword ascii
	condition:
		all of them
}

rule ArtTrayHookDll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
	strings:
		$s0 = "ArtTrayHookDll.dll" fullword ascii
		$s7 = "?TerminateHook@@YAXXZ" fullword ascii
	condition:
		all of them
}

rule sig_238_eee {
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
	strings:
		$s0 = "szj1230@yesky.com" fullword wide
		$s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
		$s4 = "MailTo:szj1230@yesky.com" fullword wide
		$s5 = "Command1_Click" fullword ascii
		$s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
		$s11 = "vb5chs.dll" fullword ascii
		$s12 = "MSVBVM50.DLL" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_asp4 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp4.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "faf991664fd82a8755feb65334e5130f791baa8c"
	strings:
		$s0 = "system.dll" fullword ascii
		$s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
		$s3 = "Public Function reboot(atype As Variant)" fullword ascii
		$s4 = "t& = ExitWindowsEx(1, atype)" ascii
		$s5 = "atype=request(\"atype\") " fullword ascii
		$s7 = "AceiveX dll" fullword ascii
		$s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
		$s10 = "sys.reboot(atype)" fullword ascii
	condition:
		all of them
}

rule aspfile1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile1.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "77b1e3a6e8f67bd6d16b7ace73dca383725ac0af"
	strings:
		$s0 = "' -- check for a command that we have posted -- '" fullword ascii
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword ascii
		$s5 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"><BODY>" fullword ascii
		$s6 = "<input type=text name=\".CMD\" size=45 value=\"<%= szCMD %>\">" fullword ascii
		$s8 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword ascii
		$s15 = "szCMD = Request.Form(\".CMD\")" fullword ascii
	condition:
		3 of them
}

rule EditServer_HackTool {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii

		$x1 = "WinEggDrop Shell Congirator" fullword ascii
	condition:
		5 of ($s*) or $x1
}

rule sig_238_letmein {
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii
	condition:
		all of them
}

rule sig_238_token {
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
	strings:
		$s0 = "Logon.exe" fullword ascii
		$s1 = "Domain And User:" fullword ascii
		$s2 = "PID=Get Addr$(): One" fullword ascii
		$s3 = "Process " fullword ascii
		$s4 = "psapi.dllK" fullword ascii
	condition:
		all of them
}

rule sig_238_TELNET {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
	strings:
		$s0 = "TELNET [host [port]]" fullword wide
		$s2 = "TELNET.EXE" fullword wide
		$s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
		$s14 = "Software\\Microsoft\\Telnet" fullword wide
	condition:
		all of them
}

rule snifferport {
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii
	condition:
		all of them
}

rule sig_238_webget {
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "GET A HTTP/1.0" fullword ascii
		$s2 = " error " fullword ascii
		$s13 = "Downloa" ascii
	condition:
		all of them
}

rule XYZCmd_zip_Folder_XYZCmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
	strings:
		$s0 = "Executes Command Remotely" fullword wide
		$s2 = "XYZCmd.exe" fullword wide
		$s6 = "No Client Software" fullword wide
		$s19 = "XYZCmd V1.0 For NT S" fullword ascii
	condition:
		all of them
}

rule ASPack_Chinese {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
	strings:
		$s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
		$s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
		$s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
		$s8 = ";  Please, translate text only after simbol '='" fullword ascii
		$s19 = "= Compress with ASPack" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIR {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii
	condition:
		all of them
}

rule sig_238_filespy {
	meta:
		description = "Disclosed hacktool set (old stuff) - file filespy.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 50
		hash = "89d8490039778f8c5f07aa7fd476170293d24d26"
	strings:
		$s0 = "Hit [Enter] to begin command mode..." fullword ascii
		$s1 = "If you are in command mode," fullword ascii
		$s2 = "[/l] lists all the drives the monitor is currently attached to" fullword ascii
		$s9 = "FileSpy.exe" fullword wide
		$s12 = "ERROR starting FileSpy..." fullword ascii
		$s16 = "exe\\filespy.dbg" fullword ascii
		$s17 = "[/d <drive>] detaches monitor from <drive>" fullword ascii
		$s19 = "Should be logging to screen..." fullword ascii
		$s20 = "Filmon:  Unknown log record type" fullword ascii
	condition:
		7 of them
}

rule ByPassFireWall_zip_Folder_Ie {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
	strings:
		$s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule EditKeyLogReadMe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLogReadMe.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dfa90540b0e58346f4b6ea12e30c1404e15fbe5a"
	strings:
		$s0 = "editKeyLog.exe KeyLog.exe," fullword ascii
		$s1 = "WinEggDrop.DLL" fullword ascii
		$s2 = "nc.exe" fullword ascii
		$s3 = "KeyLog.exe" fullword ascii
		$s4 = "EditKeyLog.exe" fullword ascii
		$s5 = "wineggdrop" fullword ascii
	condition:
		3 of them
}

rule PassSniffer_zip_Folder_readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
	strings:
		$s0 = "PassSniffer.exe" fullword ascii
		$s1 = "POP3/FTP Sniffer" fullword ascii
		$s2 = "Password Sniffer V1.0" fullword ascii
	condition:
		1 of them
}

rule sig_238_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
	strings:
		$s0 = "\"gina\"=\"gina.dll\"" fullword ascii
		$s1 = "REGEDIT4" fullword ascii
		$s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
	condition:
		all of them
}

rule splitjoin {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
	strings:
		$s0 = "Not for distribution without the authors permission" fullword wide
		$s2 = "Utility to split and rejoin files.0" fullword wide
		$s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
		$s19 = "SplitJoin" fullword wide
	condition:
		all of them
}

rule EditKeyLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
	strings:
		$s1 = "Press Any Ke" fullword ascii
		$s2 = "Enter 1 O" fullword ascii
		$s3 = "Bon >0 & <65535L" fullword ascii
		$s4 = "--Choose " fullword ascii
	condition:
		all of them
}

rule PassSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii
	condition:
		all of them
}

rule aspfile2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
	strings:
		$s0 = "response.write \"command completed success!\" " fullword ascii
		$s1 = "for each co in foditems " fullword ascii
		$s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
		$s19 = "<title>Hello! Welcome </title>" fullword ascii
	condition:
		all of them
}

rule UnPack_rar_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" fullword ascii
		$s20 = "TInject.Dll" fullword ascii

		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii
	condition:
		( 1 of ($x*) ) and ( 3 of ($s*) )
}

rule Jc_WinEggDrop_Shell {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "820674b59f32f2cf72df50ba4411d7132d863ad2"
	strings:
		$s0 = "Sniffer.dll" fullword ascii
		$s4 = ":Execute net.exe user Administrator pass" fullword ascii
		$s5 = "Fport.exe or mport.exe " fullword ascii
		$s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
		$s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
		$s15 = ": Del www.exe                   " fullword ascii
		$s20 = ":Dir *.exe                    " fullword ascii
	condition:
		2 of them
}

rule aspbackdoor_asp1 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp1.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9ef9f34392a673c64525fcd56449a9fb1d1f3c50"
	strings:
		$s0 = "param = \"driver={Microsoft Access Driver (*.mdb)}\" " fullword ascii
		$s1 = "conn.Open param & \";dbq=\" & Server.MapPath(\"scjh.mdb\") " fullword ascii
		$s6 = "set rs=conn.execute (sql)%> " fullword ascii
		$s7 = "<%set Conn = Server.CreateObject(\"ADODB.Connection\") " fullword ascii
		$s10 = "<%dim ktdh,scph,scts,jhqtsj,yhxdsj,yxj,rwbh " fullword ascii
		$s15 = "sql=\"select * from scjh\" " fullword ascii
	condition:
		all of them
}

rule QQ_zip_Folder_QQ {
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" fullword ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii
	condition:
		5 of them
}

rule UnPack_rar_Folder_TBack {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii
	condition:
		4 of them
}

rule sig_238_cmd_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
	strings:
		$s0 = "Process child = Runtime.getRuntime().exec(" ascii
		$s1 = "InputStream in = child.getInputStream();" fullword ascii
		$s2 = "String cmd = request.getParameter(\"" ascii
		$s3 = "while ((c = in.read()) != -1) {" fullword ascii
		$s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
	condition:
		all of them
}

rule RangeScan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
		$s9 = "Produced by isn0" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s20 = "%d-%d-%d %d:%d:%d" fullword ascii
	condition:
		3 of them
}

rule XYZCmd_zip_Folder_Readme {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Readme.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
	strings:
		$s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
		$s20 = "XYZCmd V1.0" fullword ascii
	condition:
		all of them
}

rule ByPassFireWall_zip_Folder_Inject {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
	strings:
		$s6 = "Fail To Inject" fullword ascii
		$s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
		$s11 = " Successfully" fullword ascii
	condition:
		all of them
}

rule sig_238_sqlcmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 40
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
	strings:
		$s0 = "Permission denial to EXEC command.:(" fullword ascii
		$s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
		$s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
		$s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
		$s6 = "SqlCmd2.exe Inside Edition." fullword ascii
		$s7 = "Http://www.patching.net  2000/12/14" fullword ascii
		$s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
	condition:
		4 of them
}

rule ASPack_ASPACK {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide
	condition:
		all of them
}

rule sig_238_2323 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii
	condition:
		all of them
}

rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
	strings:
		$s1 = "http://go.163.com/sdemo" fullword wide
		$s2 = "Player.tmp" fullword ascii
		$s3 = "Player.EXE" fullword wide
		$s4 = "mailto:sdemo@263.net" fullword ascii
		$s5 = "S-Player.exe" fullword ascii
		$s9 = "http://www.BaiXue.net (" fullword wide
	condition:
		all of them
}

rule sig_238_TFTPD32 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}

rule sig_238_iecv {
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii
	condition:
		all of them
}

rule Antiy_Ports_1_21 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s7 = "AntiyPorts MFC Application" fullword wide
		$s20 = " @Stego:" fullword ascii
	condition:
		all of them
}

rule perlcmd_zip_Folder_cmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
	strings:
		$s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
		$s1 = "s/%20/ /ig;" fullword ascii
		$s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
		$s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
		$s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
		$s6 = "$execthis = $_;" fullword ascii
		$s7 = "system($execthis);" fullword ascii
		$s12 = "s/%2f/\\//ig;" fullword ascii
	condition:
		6 of them
}

rule aspbackdoor_asp3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file asp3.txt"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
	strings:
		$s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
		$s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
		$s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
		$s14 = " Windows NT " fullword ascii
		$s16 = " WIndows 2000 " fullword ascii
		$s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
		$s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
		$s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
	condition:
		all of them
}

rule sig_238_FPipe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s3 = " -s    - outbound source port number" fullword ascii
		$s5 = "http://www.foundstone.com" fullword ascii
		$s20 = "Attempting to connect to %s port %d" fullword ascii
	condition:
		all of them
}

rule sig_238_concon {
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_regdll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file regdll.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
	strings:
		$s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
		$s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
		$s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
		$s5 = "Public Property Get oFS()" fullword ascii
	condition:
		all of them
}

rule CleanIISLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii
	condition:
		5 of them
}

rule sqlcheck {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
	strings:
		$s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
		$s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
		$s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
		$s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
		$s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
	condition:
		3 of them
}

rule sig_238_RunAsEx {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii
	condition:
		4 of them
}

rule sig_238_nbtdump {
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "Cerberus NBTDUMP" fullword ascii
		$s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
		$s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
		$s19 = "%s's password is %s</H3>" fullword wide
		$s20 = "%s's password is blank</H3>" fullword wide
	condition:
		5 of them
}

rule sig_238_Glass2k {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii
	condition:
		all of them
}

rule SplitJoin_V1_3_3_rar_Folder_3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
	strings:
		$s2 = "ie686@sohu.com" fullword ascii
		$s3 = "splitjoin.exe" fullword ascii
		$s7 = "SplitJoin" fullword ascii
	condition:
		all of them
}

rule aspbackdoor_EDIT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
	strings:
		$s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
		$s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
		$s3 = "response.write \"<a href='index.asp'>" fullword ascii
		$s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
		$s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
		$s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
		$s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
	condition:
		5 of them
}

rule aspbackdoor_entice {
	meta:
		description = "Disclosed hacktool set (old stuff) - file entice.asp"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e273a1b9ef4a00ae4a5d435c3c9c99ee887cb183"
	strings:
		$s0 = "<Form Name=\"FormPst\" Method=\"Post\" Action=\"entice.asp\">" fullword ascii
		$s2 = "if left(trim(request(\"sqllanguage\")),6)=\"select\" then" fullword ascii
		$s4 = "conndb.Execute(sqllanguage)" fullword ascii
		$s5 = "<!--#include file=sqlconn.asp-->" fullword ascii
		$s6 = "rstsql=\"select * from \"&rstable(\"table_name\")" fullword ascii
	condition:
		all of them
}

rule FPipe2_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "891609db7a6787575641154e7aab7757e74d837b"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii
	condition:
		all of them
}

rule InstGina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii
	condition:
		all of them
}

rule ArtTray_zip_Folder_ArtTray {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
	strings:
		$s0 = "http://www.brigsoft.com" fullword wide
		$s2 = "ArtTrayHookDll.dll" fullword ascii
		$s3 = "ArtTray Version 1.0 " fullword wide
		$s16 = "TRM_HOOKCALLBACK" fullword ascii
	condition:
		all of them
}

rule sig_238_findoor {
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
	strings:
		$s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
		$s8 = "PASS hacker@hacker.com" fullword ascii
		$s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
		$s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
		$s11 = "http://isno.yeah.net" fullword ascii
	condition:
		4 of them
}

rule aspbackdoor_ipclear {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
	strings:
		$s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
		$s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
		$s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
		$s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
		$s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
	condition:
		all of them
}

rule WinEggDropShellFinal_zip_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii
	condition:
		all of them
}

rule sig_238_rshsvc {
	meta:
		description = "Disclosed hacktool set (old stuff) - file rshsvc.bat"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "fb15c31254a21412aecff6a6c4c19304eb5e7d75"
	strings:
		$s0 = "if not exist %1\\rshsetup.exe goto ERROR2" fullword ascii
		$s1 = "ECHO rshsetup.exe is not found in the %1 directory" fullword ascii
		$s9 = "REM %1 directory must have rshsetup.exe,rshsvc.exe and rshsvc.dll" fullword ascii
		$s10 = "copy %1\\rshsvc.exe" fullword ascii
		$s12 = "ECHO Use \"net start rshsvc\" to start the service." fullword ascii
		$s13 = "rshsetup %SystemRoot%\\system32\\rshsvc.exe %SystemRoot%\\system32\\rshsvc.dll" fullword ascii
		$s18 = "pushd %SystemRoot%\\system32" fullword ascii
	condition:
		all of them
}

rule gina_zip_Folder_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule superscan3_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
	strings:
		$s0 = "\\scanner.ini" fullword ascii
		$s1 = "\\scanner.exe" fullword ascii
		$s2 = "\\scanner.lst" fullword ascii
		$s4 = "\\hensss.lst" fullword ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" fullword ascii
		$s9 = "\\trojans.lst" fullword ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide
	condition:
		all of them
}

rule sig_238_xsniff {
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s3 = "%s - simple sniffer for win2000" fullword ascii
		$s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s7 = "http://www.xfocus.org" fullword ascii
		$s9 = "  -pass        : Filter username/password" fullword ascii
		$s18 = "  -udp         : Output udp packets" fullword ascii
		$s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s20 = "  -tcp         : Output tcp packets" fullword ascii
	condition:
		6 of them
}

rule sig_238_fscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file fscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
	strings:
		$s0 = "FScan v1.12 - Command line port scanner." fullword ascii
		$s2 = " -n    - no port scanning - only pinging (unless you use -q)" fullword ascii
		$s5 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
		$s6 = " -z    - maximum simultaneous threads to use for scanning" fullword ascii
		$s12 = "Failed to open the IP list file \"%s\"" fullword ascii
		$s13 = "http://www.foundstone.com" fullword ascii
		$s16 = " -p    - TCP port(s) to scan (a comma separated list of ports/ranges) " fullword ascii
		$s18 = "Bind port number out of range. Using system default." fullword ascii
		$s19 = "fscan.exe" fullword wide
	condition:
		4 of them
}

rule _iissample_nesscan_twwwscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword
	condition:
		all of them
}

rule _FsHttp_FsPop_FsSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
		hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
		hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
	strings:
		$s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
		$s1 = "-ERR Get SMS Users ID Failed" fullword
		$s2 = "Control Time Out 90 Secs, Connection Closed" fullword
		$s3 = "-ERR Post SMS Failed" fullword
		$s4 = "Current.hlt" fullword
		$s6 = "Histroy.hlt" fullword
		$s7 = "-ERR Send SMS Failed" fullword
		$s12 = "-ERR Change Password <New Password>" fullword
		$s17 = "+OK Send SMS Succussifully" fullword
		$s18 = "+OK Set New Password: [%s]" fullword
		$s19 = "CHANGE PASSWORD" fullword
	condition:
		all of them
}

rule Ammyy_Admin_AA_v3 {
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii

		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii
	condition:
		2 of ($x*) or all of ($s*)
}

/* Other dumper and custom hack tools */

rule LinuxHacktool_eyes_screen {
	meta:
		description = "Linux hack tools - file screen"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "a240a0118739e72ff89cefa2540bf0d7da8f8a6c"
	strings:
		$s0 = "or: %s -r [host.tty]" fullword ascii
		$s1 = "%s: process: character, ^x, or (octal) \\032 expected." fullword ascii
		$s2 = "Type \"screen [-d] -r [pid.]tty.host\" to resume one of them." fullword ascii
		$s6 = "%s: at [identifier][%%|*|#] command [args]" fullword ascii
		$s8 = "Slurped only %d characters (of %d) into buffer - try again" fullword ascii
		$s11 = "command from %s: %s %s" fullword ascii
		$s16 = "[ Passwords don't match - your armor crumbles away ]" fullword ascii
		$s19 = "[ Passwords don't match - checking turned off ]" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_scanssh {
	meta:
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_pscan2 {
	meta:
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_a {
	meta:
		description = "Linux hack tools - file a"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "mv scan.log bios.txt" fullword ascii
		$s2 = "rm -rf bios.txt" fullword ascii
		$s3 = "echo -e \"# by Eyes.\"" fullword ascii
		$s4 = "././pscan2 $1 22" fullword ascii
		$s10 = "echo \"#cautam...\"" fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_mass {
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii
	condition:
		1 of them
}

rule LinuxHacktool_eyes_pscan2_2 {
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii
	condition:
		2 of them
}

rule CN_Portscan : APT
{
    meta:
        description = "CN Port Scanner"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
    	$s1 = "MZ"
		$s2 = "TCP 12.12.12.12"
    condition:
        ($s1 at 0) and $s2
}

rule WMI_vbs : APT
{
    meta:
        description = "WMI Tool - APT"
        author = "Florian Roth"
        release_date = "2013-11-29"
        confidential = false
		score = 70
    strings:
		$s3 = "WScript.Echo \"   $$\\      $$\\ $$\\      $$\\ $$$$$$\\ $$$$$$$$\\ $$\\   $$\\ $$$$$$$$\\  $$$$$$"
    condition:
        all of them
}

rule CN_Toolset__XScanLib_XScanLib_XScanLib {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}

rule CN_Toolset_NTscan_PipeCmd {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
	strings:
		$s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s3 = "PipeCmd.exe" fullword wide
		$s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s5 = "%s\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
		$s9 = "PipeCmdSrv.exe" fullword ascii
		$s10 = "This is a service executable! Couldn't start directly." fullword ascii
		$s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
		$s14 = "PIPECMDSRV" fullword wide
		$s15 = "PipeCmd Service" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset_LScanPortss_2 {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}

rule CN_Toolset_sig_1433_135_sqlr {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		reference2 = "https://raw.githubusercontent.com/Neo23x0/Loki/master/signatures/thor-hacktools.yar"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}


/* Mimikatz */

rule Mimikatz_Memory_Rule_1 : APT {
	meta:
		author = "Florian Roth"
		date = "12/22/2014"
		score = 70
		type = "memory"
		description = "Detects password dumper mimikatz in memory"
	strings:
		$s1 = "sekurlsa::msv" fullword ascii
	    $s2 = "sekurlsa::wdigest" fullword ascii
	    $s4 = "sekurlsa::kerberos" fullword ascii
	    $s5 = "sekurlsa::tspkg" fullword ascii
	    $s6 = "sekurlsa::livessp" fullword ascii
	    $s7 = "sekurlsa::ssp" fullword ascii
	    $s8 = "sekurlsa::logonPasswords" fullword ascii
	    $s9 = "sekurlsa::process" fullword ascii
	    $s10 = "ekurlsa::minidump" fullword ascii
	    $s11 = "sekurlsa::pth" fullword ascii
	    $s12 = "sekurlsa::tickets" fullword ascii
	    $s13 = "sekurlsa::ekeys" fullword ascii
	    $s14 = "sekurlsa::dpapi" fullword ascii
	    $s15 = "sekurlsa::credman" fullword ascii
	condition:
		1 of them
}

rule Mimikatz_Memory_Rule_2 : APT {
	meta:
		description = "Mimikatz Rule generated from a memory dump"
		author = "Florian Roth - Florian Roth"
		type = "memory"
		score = 80
	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii
	condition:
		$s0 and 1 of ($x*)
}

rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"
      score          = 80
	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }

		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }

		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}


rule mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase

	condition:
		(uint32(0) == 0x504d444d) and $lsass
}


rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }

	condition:
		$asn1 at 0
}


rule wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"

	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}


rule lsadump
{
	meta:
		description		= "LSA dump programe (bootkey/syskey) - pwdump and others"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$str_sam_inc	= "\\Domains\\Account" ascii nocase
		$str_sam_exc	= "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call	= {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa	= { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey		= { 4b 53 53 4d [20-70] 05 00 01 00}

	condition:
		( ($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not uint16(0) == 0x5a4d
}

rule Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth"
		score = 80
		date = "2015/03/31"
		reference = "https://github.com/Neo23x0/Loki/blob/master/signatures/thor-hacktools.yar"
	strings:
		$s1 = "SID               :" ascii fullword
		$s2 = "* NTLM     :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword
	condition:
		all of them
}

rule AppInitHook {
	meta:
		description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/Z292v6"
		date = "2015-07-15"
		score = 70
		hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
	strings:
		$s0 = "\\Release\\AppInitHook.pdb" ascii
		$s1 = "AppInitHook.dll" fullword ascii
		$s2 = "mimikatz.exe" fullword wide
		$s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
		$s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
		$s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
		$s6 = "VoidFunc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule VSSown_VBS {
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii
	condition:
		all of them
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_Wineggdrop.yar*/
rule wineggdrop : portscanner toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for TCP Portscanner VX.X by WinEggDrop"
        in_the_wild = true
        family = "Hackingtool/Portscanner"

    strings:
        $a = { 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72 
               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44 
               72 6f 70 0a } 
        $b = "Result.txt"
        $c = "Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        //check for wineggdrop specific strings
        $a and $b and $c 
}

/*https://github.com/Yara-Rules/rules/blob/master/malware/TOOLKIT_exe2hex_payload.yar*/
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-15
	Identifier: Exe2hex
*/

rule Payload_Exe2Hex : toolkit {
	meta:
		description = "Detects payload generated by exe2hex"
		author = "Florian Roth"
		reference = "https://github.com/g0tmi1k/exe2hex"
		date = "2016-01-15"
		score = 70
	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii
	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
