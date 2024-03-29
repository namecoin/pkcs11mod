$ErrorActionPreference = "Stop"

Write-Host "Checking pkcs11proxy..."

if ( ( .\Dependencies.exe -exports .\pkcs11proxy.dll | Select-String -Pattern "C_GetFunctionList" -SimpleMatch -Quiet ) -ne $true ) {
    Write-Host "pkcs11proxy export test failed"
    exit 111
}

Write-Host "Checking p11proxy..."

if ( ( .\Dependencies.exe -exports .\p11proxy.dll | Select-String -Pattern "C_GetFunctionList" -SimpleMatch -Quiet ) -ne $true ) {
    Write-Host "p11proxy export test failed"
    exit 111
}

Write-Host "Export tests passed"

exit 0
