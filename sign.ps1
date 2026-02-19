# sign.ps1 — підписати SecureShare.exe self-signed сертифікатом
# Запускати після кожного rebuild:  .\sign.ps1

$exePath  = "$PSScriptRoot\dist\SecureShare.exe"
# Set your certificate thumbprint here (from: Get-ChildItem Cert:\CurrentUser\My)
$certThumb = $env:SECURESHARE_CERT_THUMBPRINT
if (-not $certThumb) {
    Write-Host "ERROR: Set SECURESHARE_CERT_THUMBPRINT environment variable"
    Write-Host "  Example: `$env:SECURESHARE_CERT_THUMBPRINT = 'YOUR_THUMBPRINT'"
    exit 1
}

$cert = Get-Item "Cert:\CurrentUser\My\$certThumb" -ErrorAction Stop

$result = Set-AuthenticodeSignature `
    -FilePath    $exePath `
    -Certificate $cert `
    -HashAlgorithm SHA256

if ($result.Status -eq "Valid") {
    Write-Host "Signed OK: $exePath"
    Write-Host "  Signer : $($result.SignerCertificate.Subject)"
    Write-Host "  Valid  : $($result.SignerCertificate.NotAfter)"
} else {
    Write-Host "ERROR: $($result.StatusMessage)"
    exit 1
}
