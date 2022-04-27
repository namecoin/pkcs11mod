$ErrorActionPreference = "Stop"

Write-Host "===== init DB ====="

& "./certutil.exe" -N -d . --empty-password

Write-Host "===== Default System CKBI ====="

& "./certutil.exe" -L -d . -h all | Tee-Object -FilePath "list-all-default.txt"
If (!$?) {
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

if (! ( Select-String -Quiet -CaseSensitive -SimpleMatch -Pattern ",C," -Path "list-all-default.txt" ) ) {
  Write-Host "No trusted certs found!"
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "missing"
If (!$?) {
  exit 222
}

Write-Host "===== System CKBI via pkcs11proxy ====="

Move-Item -Path "$Env:CI_MAIN_MODULE" -Destination "$Env:CI_BAK_MODULE"

$Env:PKCS11PROXY_CKBI_TARGET = "$Env:CI_BAK_MODULE"
Copy-Item pkcs11proxy.dll -Destination "$Env:CI_MAIN_MODULE"

& "./certutil.exe" -L -d . -h all | Tee-Object -FilePath "list-all-pkcs11proxy.txt"
If (!$?) {
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

if (! ( Select-String -Quiet -CaseSensitive -SimpleMatch -Pattern ",C," -Path "list-all-pkcs11proxy.txt" ) ) {
  Write-Host "No trusted certs found!"
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

Write-Host "===== System CKBI diff via pkcs11proxy ====="

$pkcs11proxydiff = Compare-Object -CaseSensitive -SyncWindow 0 (Get-Content "list-all-default.txt") (Get-Content "list-all-pkcs11proxy.txt")
Write-Host $pkcs11proxydiff

if ($pkcs11proxydiff.Length -gt 0) {
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}

Write-Host "===== System CKBI via p11proxy ====="

$Env:P11PROXY_CKBI_TARGET = "$Env:CI_BAK_MODULE"
Copy-Item p11proxy.dll -Destination "$Env:CI_MAIN_MODULE"

& "./certutil.exe" -L -d . -h all | Tee-Object -FilePath "list-all-p11proxy.txt"
If (!$?) {
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

if (! ( Select-String -Quiet -CaseSensitive -SimpleMatch -Pattern ",C," -Path "list-all-p11proxy.txt" ) ) {
  Write-Host "No trusted certs found!"
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

Write-Host "===== System CKBI diff via p11proxy ====="

$p11proxydiff = Compare-Object -CaseSensitive -SyncWindow 0 (Get-Content "list-all-default.txt") (Get-Content "list-all-p11proxy.txt")
Write-Host $p11proxydiff

if ($p11proxydiff.Length -gt 0) {
  & "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/dump-proxy-log-fail.ps1"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/assert-proxy-log.ps1" -desired "present"
If (!$?) {
  exit 222
}

