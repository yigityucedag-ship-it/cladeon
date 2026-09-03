<#
.SYNOPSIS
  Build the Cladeon MSIX package.

.DESCRIPTION
  Two modes, and the difference matters.

  Without -Sign, this produces an unsigned .msix. That is the file you upload to
  Partner Center. Microsoft re-signs it with their own certificate on the way into
  the Store, which is the whole point of publishing there: nobody has to buy a
  code-signing certificate, and the Windows warning never appears.

  With -Sign, it also signs the package with a self-signed certificate so it can be
  installed on this machine to test. That certificate is only trusted on machines
  where it has been installed into the Trusted People store, so it is for local
  testing and nothing else. Never send a self-signed build to anyone.

  -Publisher must match the Publisher in the manifest exactly, character for
  character, or Windows refuses the package with an unhelpful error. Partner Center
  gives you the real values under Product Identity once the app name is reserved.

.EXAMPLE
  # Local test build, installable on this machine
  .\build.ps1 -Sign

.EXAMPLE
  # The real thing, using the identity Partner Center issued
  .\build.ps1 -IdentityName 12345MyPublisher.Cladeon `
              -Publisher "CN=ABCD1234-5678-90AB-CDEF-1234567890AB" `
              -PublisherDisplayName "Yigit Murat Yucedag"
#>
[CmdletBinding()]
param(
  [string] $IdentityName          = "PLACEHOLDER.Cladeon",
  [string] $Publisher             = "CN=PLACEHOLDER",
  [string] $PublisherDisplayName  = "PLACEHOLDER",
  [string] $Version               = "0.1.0.0",
  [switch] $Sign,
  [string] $OutDir                = (Join-Path $PSScriptRoot "out")
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# ---- locate the SDK tools ---------------------------------------------------
function Find-SdkTool([string] $name) {
  $roots = @(
    "C:\Program Files (x86)\Windows Kits\10\bin",
    "C:\Program Files\Windows Kits\10\bin"
  ) | Where-Object { Test-Path $_ }
  $hit = $roots |
    ForEach-Object { Get-ChildItem $_ -Recurse -Filter $name -ErrorAction SilentlyContinue } |
    Where-Object { $_.FullName -match "\\x64\\" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if (-not $hit) { throw "$name not found. Install the Windows SDK (Windows App SDK / MSIX packaging tools)." }
  return $hit.FullName
}

$makeappx = Find-SdkTool "makeappx.exe"
Write-Host "makeappx : $makeappx"

# ---- build the binaries -----------------------------------------------------
Write-Host "`nBuilding release binaries..."
Push-Location $repo
try {
  & cargo build --release --workspace
  if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally { Pop-Location }

# ---- lay out the package ----------------------------------------------------
$stage = Join-Path $OutDir "stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stage "Scanner") -Force | Out-Null

Copy-Item (Join-Path $repo "target\release\cladeon.exe")        (Join-Path $stage "Cladeon.exe")
Copy-Item (Join-Path $repo "target\release\cladeon-screen.exe") (Join-Path $stage "Scanner\cladeon-screen.exe")
Copy-Item (Join-Path $PSScriptRoot "Assets") $stage -Recurse

# The manifest is written per build rather than edited in place, so a real
# submission never depends on someone remembering to put the placeholders back.
$manifest = Get-Content (Join-Path $PSScriptRoot "AppxManifest.xml") -Raw
$manifest = $manifest.Replace('Name="PLACEHOLDER.Cladeon"',        "Name=`"$IdentityName`"")
$manifest = $manifest.Replace('Publisher="CN=PLACEHOLDER"',        "Publisher=`"$Publisher`"")
$manifest = $manifest.Replace('Version="0.1.0.0"',                 "Version=`"$Version`"")
$manifest = $manifest.Replace('<PublisherDisplayName>PLACEHOLDER</PublisherDisplayName>',
                              "<PublisherDisplayName>$PublisherDisplayName</PublisherDisplayName>")
Set-Content -Path (Join-Path $stage "AppxManifest.xml") -Value $manifest -Encoding UTF8

# ---- pack -------------------------------------------------------------------
$msix = Join-Path $OutDir "Cladeon.msix"
if (Test-Path $msix) { Remove-Item $msix -Force }
Write-Host "`nPacking..."
& $makeappx pack /d $stage /p $msix /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }

# ---- optionally sign, for local testing only --------------------------------
if ($Sign) {
  $signtool = Find-SdkTool "signtool.exe"
  $cert = Get-ChildItem Cert:\CurrentUser\My |
          Where-Object { $_.Subject -eq $Publisher } |
          Select-Object -First 1
  if (-not $cert) {
    Write-Host "Creating a self-signed test certificate for $Publisher ..."
    $cert = New-SelfSignedCertificate -Type Custom -Subject $Publisher `
      -KeyUsage DigitalSignature -FriendlyName "Cladeon local test" `
      -CertStoreLocation "Cert:\CurrentUser\My" `
      -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
  }
  & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $msix
  if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
  Write-Host "`nSigned with a LOCAL TEST certificate. Do not distribute this file."
  Write-Host "To trust it on this machine, run as administrator:"
  Write-Host "  Export-Certificate -Cert Cert:\CurrentUser\My\$($cert.Thumbprint) -FilePath cladeon-test.cer"
  Write-Host "  Import-Certificate -FilePath cladeon-test.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople"
}

$size = "{0:N1} MB" -f ((Get-Item $msix).Length / 1MB)
Write-Host "`nBuilt $msix  ($size)"
if (-not $Sign) {
  Write-Host "Unsigned, which is correct for a Partner Center upload."
}
