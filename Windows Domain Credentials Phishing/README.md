VirusTotal detects this as a keylogger. There are other methods, like with powershell to collect user credentials, once a foothold is obtained and clear text credentials are wanted or needed.

Get-FileHash .\OUTLOOK.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          037A3AF124659D30B18C0A2F5D8739126266865326408063ABAD8980C268E8AB


When scanned with Windows Defender this is not detected as malicious.
