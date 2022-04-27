param (
  $channel
)

$ErrorActionPreference = "Stop"

if ( "$channel" -eq "Nightly" ) {
    $TBBVersion = ( ( Invoke-WebRequest -UseBasicParsing "https://nightlies.tbb.torproject.org/nightly-builds/tor-browser-builds/" ).Links | Where-Object {$_.href -match 'tbb'} )[0].href

    $URL = "https://nightlies.tbb.torproject.org/nightly-builds/tor-browser-builds/${TBBVersion}nightly-windows-x86_64/mar-tools-win64.zip"
}
elseif ( "$channel" -eq "Alpha" ) {
    $TBBVersion = ( ( Invoke-WebRequest -UseBasicParsing "https://dist.torproject.org/torbrowser/?C=M;O=D" ).Links | Where-Object {$_.href -match '[0-9]'} | Where-Object {$_.href -match 'a'} )[0].href

    $URL = "https://dist.torproject.org/torbrowser/${TBBVersion}mar-tools-win64.zip"
}
elseif ( "$channel" -eq "Stable" ) {
    $TBBVersion = ( ( Invoke-WebRequest -UseBasicParsing "https://dist.torproject.org/torbrowser/?C=M;O=D" ).Links | Where-Object {$_.href -match '[0-9]'} | Where-Object {$_.href -notmatch 'a'} )[0].href

    $URL = "https://dist.torproject.org/torbrowser/${TBBVersion}mar-tools-win64.zip"
}
else {
    Write-Host "Invalid channel $channel"
    exit 1
}

Write-Host "$URL"

& curl -o "mar-tools.zip" "$URL"
If (!$?) {
  exit 222
}

& tar -xf "mar-tools.zip"
If (!$?) {
  exit 222
}

mv ./mar-tools/* ./
