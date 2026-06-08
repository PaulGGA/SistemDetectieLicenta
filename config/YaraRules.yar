import "pe"

rule APIInstall
{
    meta: 
        description = "Detects API calls that may be used for installing other malware"
        author = "LicentaAntivirus"

    strings:
        $text1 = "CreateRemoteThread" ascii wide
        $text2 = "VirtualAlloc" ascii wide
        $text3 = "WriteProcessMemory" ascii wide
        $text4 = "OpenProcess" ascii wide
        $text5 = "QueueUserAPC" ascii wide
        $text6 = "NtUnmapViewOfSection" wide ascii
    condition:
        ($text1 and $text3)or ($text2 and $text3 and $text4) or $text5 or $text6 or
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("kernel32.dll", "WriteProcessMemory")
        )
}

rule APIKeys
{
    meta:
        description = "Detects API calls that are used to capture the users keyboard"
        author = "LicentaAntivirus"

    strings:
        $specific1 = "SetWindowsHookEx" ascii wide
        $specific2 = "GetAsyncKeyState" ascii wide
        $specific3 = "CallNextHookEx" ascii wide
        $specific4 = "GetRawInputData" ascii wide

        $normal1 = "GetKeyboardState" ascii wide
        $normal2 = "GetKeyNameText" ascii wide
        $normal3 = "GetWindowsText" ascii wide
        $normal4 = "GetForegroundWindow" ascii wide

    condition:
        any of ($specific*) or ($normal1 and $normal3) or ($normal2 and $normal3 and $normal4) or 
        (
            pe.imports("*", "SetWindowsHookEx") or
            pe.imports("*", "GetAsyncKeyState") or
            pe.imports("*", "CallNextHookEx")
        )
}

rule APIHooking
{
    meta: 
        description = "Detects API calls that may be used intercept API calls and modify them to avoid detection"
        author = "LicentaAntivirus"

    strings:
        $specific1 = "DetourAttach" ascii wide
        $specific2 = "SetThreadContext" ascii wide
        $specific3 = "GetThreadContext" ascii wide
        $specific4 = "VirtualProtectEx" ascii wide
        
        $common1 = "GetProcAddress" ascii wide
        $common2 = "LoadLibrary" ascii wide
        $common3 = "VirtualProtect" ascii wide
        $common4 = "SetWindowsHookEx" ascii wide
        $common5 = "GetModuleHandle" ascii wide

    condition:
        any of ($specific*) or
        (3 of ($common*) and pe.imports("user32.dll", "SetWindowsHookExA")) or
        pe.imports("*", "DetourAttach")
}


rule APIDownloads
{
    meta: 
        description = "Detects API calls that may be used for downloading other malware"
        author = "LicentaAntivirus"

    strings:
        $text1 = "URLDownloadToFile" ascii wide
        $text2 = "WinHttpOpen" ascii wide
        $text3 = "WinHttpConnect" ascii wide
        $text4 = "WinHttpOpenRequest" ascii wide
        $text5 = "WinHttpSendRequest" ascii wide
        $text6 = "InternetReadFile" ascii wide
        $text7 = "InternetWriteFile" ascii wide
        

    condition:
        any of ($text*) or
       (
            pe.imports("*", "URLDownloadToFileA") or
            pe.imports("*", "URLDownloadToFileW") or
            pe.imports("*", "WinHttpOpen") or
            pe.imports("*", "WinHttpConnect") or
            pe.imports("*", "WinHttpSendRequest") or
            pe.imports("*", "InternetReadFile")
        )

}

rule APIComunicate
{
     meta: 
        description = "Detects API calls that may be used for comunicating with the attacker"
        author = "LicentaAntivirus"

    strings:
        $text1 = "InternetConnect" ascii wide
        $text2 = "InternetOpen" ascii wide
        $text3 = "InternetOpenUrl" ascii wide
        $text4 = "HttpOpenRequest" ascii wide
        $text5 = "HttpSendRequest" ascii wide

    condition:
        any of ($text*) or
         (
            pe.imports("*", "InternetConnect") or
            pe.imports("*", "InternetOpen") or
            pe.imports("*", "HttpOpenRequest") or
            pe.imports("*", "HttpSendRequest")
        )
}

rule APIExfiltration
{
    meta: 
        description = "Detects API calls that may be used for exfiltrating data"
        author = "LicentaAntivirus"

    strings:

        

        $normal1 = "InternetReadFile" ascii wide
        $normal2 = "WSASend" ascii wide
        $normal3 = "GetClipboardData" ascii wide
        $specific2 = "InternetWriteFile" ascii wide
        $specific1 = "FtpPutFile" ascii wide

    condition:
        any of ($specific*) or
        ($normal2 and $normal3) or ($normal1 and $normal2) or
        (
            pe.imports("*", "InternetWriteFile") or
            pe.imports("*", "FtpPutFile")
        )

}




rule APIAntiDebugVMDetection
{
    meta: 
        description = "Detects API calls that may be used for seeing if the malware it's being analyzed or is running in a virtual machine"
        author = "LicentaAntivirus"

   

    strings:
        $specific1 = "IsDebuggerPresent" ascii wide
        $specific2 = "CheckRemoteDebuggerPresent" ascii wide
        $specific3 = "NtQueryInformationProcess" ascii wide
        
        $common1 = "GetTickCount" ascii wide
        $common2 = "GetSystemMetrics" ascii wide
        $common3 = "OutputDebugString" ascii wide
        $common4 = "RegQueryValueEx" ascii wide

    condition:
        any of ($specific*) or
        3 of ($common*) or
        pe.imports("*", "CheckRemoteDebuggerPresent") or
        pe.imports("*", "NtQueryInformationProcess")
}



rule APICrypt
{
    meta: 
        description = "Detects API calls that may be used for ransomware attacks"
        author = "LicentaAntivirus"

    strings:
        $text1 = "CryptEncrypt" ascii wide
        $text2 = "CryptDecrypt" ascii wide
        $text3 = "CryptAcquireContext" ascii wide
        $text4 = "CryptReleaseContext" ascii wide
        $text5 = "CryptGenKey" ascii wide
        $text6 = "CryptDeriveKey" ascii wide
        $text7 = "CryptCreateHash" ascii wide

    condition:
        any of ($text*) or
        (
            pe.imports("*", "CryptEncrypt") or
            pe.imports("*", "CryptDecrypt") or
            pe.imports("*", "CryptAcquireContextA") or
            pe.imports("*", "CryptAcquireContextW") or
            pe.imports("*", "CryptGenKey")
        )
}