rule MAL_RANSOM_Cerber {
		meta: 
			description = "Detects Cerber ransomware cryptor binary based on embedded strings and IP addresses"	
			author = "Null_Syntax"
			reference = "https://www.virustotal.com/gui/file/c5b70adfa23ae3802e8b51560c64635911869b412cc1e8c1f6e1904334c0abe9/detection"
			date = "2026-05-01"
			hash1 = "c5b70adfa23ae3802e8b51560c64635911869b412cc1e8c1f6e1904334c0abe9"
			hash2 = "3a3b631dbba06c1928d2398570585cb66493bc230038c786aa205c0256ebc519"
			hash3 = "4ed46b98d047f5ed26553c6f4fded7209933ca9632b998d265870e3557a5cdfe"
			hash4 = "1849bc76e4f9f09fc6c88d5de1a7cb304f9bc9d338f5a823b7431694457345bd"
			hash5 = "ce51278578b1a24c0fc5f8a739265e88f6f8b32632cf31bf7c142571eb22e243"
			tags = "Cerber, Ransomware"
			version = "1.0"

		strings:
			$ransom_note1 = "_README_.hta" nocase wide ascii
			$ransom_note2 = "_HELP_HELP_HELP_" nocase wide ascii
			$mutex = "Shell.TrayWnd" nocase wide ascii
			$ext1 = ".cerber" nocase wide ascii
			$ext2 = ".crypt" nocase wide ascii
			$ext3 = ".a769" nocase wide ascii
			$ext4 = ".locked" nocase wide ascii
			$C2_tag = "C3RB3R" nocase wide ascii
			$reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase wide ascii
			$reg_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase wide ascii
			$reg_policy = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase wide ascii
			$reg_autorun = "Software\\Microsoft\\Command Processor\\AutoRun" nocase wide ascii
			$reg_pending = "PendingFileRenameOperations" nocase wide ascii
			$ip_range1 = "15.93.12"
			$ip_range2 = "63.55.11"
			$ip_range3 = "194.165.16"
			$C2_ip = "45.145.6.112"
			$payload = "agttydcb" nocase wide ascii
			$cryptor_marker = "agttydck" nocase wide ascii

		condition:
			// Path 1: Ransom indicators + technical confirmation
			(1 of ($ransom_note*, $ext*) and 1 of ($C2_tag, $cryptor_marker, $ip_range*, $C2_ip, $reg_*, $mutex))
			or
			// Path 2: Multiple technical indicators without obvious ransom strings
			(2 of ($C2_tag, $cryptor_marker, $payload, $ip_range*, $C2_ip) and 1 of ($reg_*, $mutex))
}