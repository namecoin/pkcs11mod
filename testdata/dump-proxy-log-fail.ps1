$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "!!!!! Test failed, dumping proxy log... !!!!!"
Write-Host ""

Get-Content -ErrorAction SilentlyContinue "$Env:APPDATA/pkcs11proxy.log"
Get-Content -ErrorAction SilentlyContinue "./pkcs11proxy.log"
Get-Content -ErrorAction SilentlyContinue "$Env:APPDATA/p11proxy.log"
Get-Content -ErrorAction SilentlyContinue "./p11proxy.log"

exit 1
