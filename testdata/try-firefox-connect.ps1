param (
  $server_host,
  $desired
)

$ErrorActionPreference = "Stop"

Write-Host "$server_host"

if ( ("$desired" -ne "success" ) -and ( "$desired" -ne "fail" ) ) {
    Write-Host "Invalid DESIRED value; should be success or fail"
    exit 1
}

# Nuke whatever cached state might exist...
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$Env:APPDATA/$Env:CI_APPDATA"

& "$Env:CI_MAIN_EXE" --screenshot "https://$server_host"
Start-Sleep -seconds 10
Stop-Process -Name "firefox" -ErrorAction SilentlyContinue
Start-Sleep -seconds 5

if ( Test-Path -Path "screenshot.png" ) {
    $result = "success"
}
else {
    $result = "fail"
}

Remove-Item -Force -ErrorAction SilentlyContinue "screenshot.png"

if ( "$result" -ne "$desired" ) {
    Write-Host "TLS test failed"
    Write-Host "Got $result, wanted $desired"
    exit 1
}

exit 0
