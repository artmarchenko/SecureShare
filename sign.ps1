# sign.ps1 — підписати SecureShare.exe self-signed сертифікатом
# Запускати після кожного rebuild:  .\sign.ps1

$exePath  = "$PSScriptRoot\dist\SecureShare.exe"
$certThumb = "AD2D7C0976DA576F4205D3FBCECA977A2246C416"

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
