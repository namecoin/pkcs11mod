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

if ( "$Env:CI_DISABLE_E10S" -eq "1" ) {
    $e10s_version = ( Get-Item "$Env:CI_MAIN_EXE" ).VersionInfo.ProductVersion
    $Env:MOZ_FORCE_DISABLE_E10S = $e10s_version
    Write-Host "Disabled Electrolysis for version $e10s_version"
}

# Try multiple times, since network failures might happen.  If at least 1
# connection succeeds, the result is success.

$result = "fail"

foreach ($i in 1..3) {
    # Nuke whatever cached state might exist...
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$Env:APPDATA/$Env:CI_APPDATA"

    & "$Env:CI_MAIN_EXE" --screenshot "https://$server_host"
    Start-Sleep -seconds 10
    Stop-Process -Name ( [System.IO.Path]::GetFileNameWithoutExtension("$Env:CI_MAIN_EXE") ) -ErrorAction SilentlyContinue
    Start-Sleep -seconds 5

    if ( Test-Path -Path "screenshot.png" ) {
        $result = "success"
    }

    Remove-Item -Force -ErrorAction SilentlyContinue "screenshot.png"

    if ( "$result" -eq "success" ) {
        break
    }

    Start-Sleep -seconds 5
}

if ( "$result" -ne "$desired" ) {
    Write-Host "TLS test failed"
    Write-Host "Got $result, wanted $desired"
    exit 1
}

exit 0
