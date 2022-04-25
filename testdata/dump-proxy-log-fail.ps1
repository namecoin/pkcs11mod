$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "!!!!! Test failed, dumping proxy log... !!!!!"
Write-Host ""

Get-Content -ErrorAction SilentlyContinue "$Env:APPDATA/pkcs11mod.log"
Get-Content -ErrorAction SilentlyContinue "./pkcs11mod.log"

exit 1
