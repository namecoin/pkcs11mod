param (
  $desired
)

$ErrorActionPreference = "Stop"

if ( ("$desired" -ne "present" ) -and ( "$desired" -ne "missing" ) ) {
    Write-Host "Invalid DESIRED value; should be present or missing"
    exit 1
}

if ( ( Test-Path -Path "$Env:APPDATA/pkcs11proxy.log" ) -Or ( Test-Path -Path "./pkcs11proxy.log" ) ) {
    $result="present"
}
else {
    $result="missing"
}

Remove-Item -Force -ErrorAction SilentlyContinue "$Env:APPDATA/pkcs11proxy.log"
Remove-Item -Force -ErrorAction SilentlyContinue "./pkcs11proxy.log"

if ( "$result" -ne "$desired" ) {
    Write-Host "Log test failed"
    Write-Host "Got $result, wanted $desired"
    exit 1
}

exit 0
