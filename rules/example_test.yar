rule Contains_EICAR_String {
    meta:
        description = "Educational test rule for EICAR string"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Keywords {
    meta:
        description = "Educational rule to flag suspicious PowerShell keywords"
        severity = "medium"
    strings:
        $s1 = "IEX(" nocase
        $s2 = "DownloadString" nocase
        $s3 = "powershell -enc" nocase
    condition:
        any of ($s*)
}
