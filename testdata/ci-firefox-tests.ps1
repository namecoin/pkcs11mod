$ErrorActionPreference = "Stop"

Write-Host "===== Default System CKBI ====="

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "www.namecoin.org" -desired "success"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "missing"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "untrusted-root.badssl.com" -desired "fail"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "missing"
If (!$?) {
  exit 222
}

Write-Host "===== Deleted System CKBI ====="

Move-Item -Path "$Env:CI_MAIN_MODULE" -Destination "$Env:CI_BAK_MODULE"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "www.namecoin.org" -desired "fail"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "missing"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "untrusted-root.badssl.com" -desired "fail"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "missing"
If (!$?) {
  exit 222
}

# TODO: No env var, -desired "missing" default target

# TODO: Env var pointing to -desired "missing" target

Write-Host "===== System CKBI via pkcs11proxy ====="

$Env:PKCS11PROXY_CKBI_TARGET = "$Env:CI_BAK_MODULE"
Copy-Item pkcs11proxy.dll -Destination "$Env:CI_MAIN_MODULE"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "www.namecoin.org" -desired "success"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "untrusted-root.badssl.com" -desired "fail"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}

Write-Host "===== System CKBI via p11proxy ====="

$Env:P11PROXY_CKBI_TARGET = "$Env:CI_BAK_MODULE"
Copy-Item p11proxy.dll -Destination "$Env:CI_MAIN_MODULE"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "www.namecoin.org" -desired "success"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-firefox-connect.ps1" -server_host "untrusted-root.badssl.com" -desired "fail"
If (!$?) {
  exit 222
}
& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}
