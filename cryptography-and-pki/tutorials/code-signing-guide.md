# Code Signing Complete Guide

## Table of Contents
- [Introduction to Code Signing](#introduction-to-code-signing)
- [Code Signing Certificates](#code-signing-certificates)
- [Platform-Specific Signing](#platform-specific-signing)
- [Timestamping](#timestamping)
- [Security Best Practices](#security-best-practices)
- [Verification and Validation](#verification-and-validation)
- [Troubleshooting](#troubleshooting)

## Introduction to Code Signing

Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted since it was signed.

### Why Code Sign?

**Benefits:**
- **Authentication**: Verify the publisher's identity
- **Integrity**: Ensure code hasn't been tampered with
- **Trust**: Build user confidence in your software
- **Security**: Reduce malware distribution
- **Compliance**: Meet app store and platform requirements

**Use Cases:**
- Desktop applications (Windows, macOS, Linux)
- Mobile apps (iOS, Android)
- Browser extensions
- Scripts and macros
- Container images
- Firmware updates

### How Code Signing Works

```
1. Developer generates key pair (private + public)
2. CA issues code signing certificate
3. Developer signs code with private key
4. Signature attached to code
5. User downloads signed code
6. OS/Platform verifies signature using public key in certificate
7. If valid, code executes; if invalid, warning/block
```

## Code Signing Certificates

### Certificate Types

#### Standard Code Signing Certificate

- Basic identity validation
- Suitable for most developers
- Immediate SmartScreen reputation building required

#### Extended Validation (EV) Code Signing Certificate

- Rigorous identity validation
- Hardware token required (USB or HSM)
- Instant SmartScreen reputation (Windows)
- Higher trust level
- Required for kernel-mode drivers (Windows)

### Obtaining Certificates

#### Commercial Certificate Authorities

**Popular CAs:**
- DigiCert
- Sectigo (formerly Comodo)
- GlobalSign
- Entrust
- SSL.com

```bash
# Generate private key and CSR
openssl req -new -newkey rsa:3072 -nodes \
  -keyout codesign.key -out codesign.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=Developer Name" \
  -addext "keyUsage=digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

# Submit CSR to CA
# Complete identity verification
# Receive certificate
```

#### Self-Signed Certificates (Testing Only)

```bash
# Create self-signed code signing certificate
openssl req -x509 -newkey rsa:3072 -keyout codesign.key \
  -out codesign.crt -days 365 -nodes \
  -subj "/CN=Test Developer" \
  -addext "keyUsage=digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

# Convert to PKCS#12 format
openssl pkcs12 -export -out codesign.pfx \
  -inkey codesign.key -in codesign.crt \
  -name "Test Code Signing Certificate"
```

⚠️ **Warning**: Self-signed certificates are only for testing. Users will see security warnings.

### Certificate Storage

#### Hardware Security Module (HSM)

```bash
# AWS CloudHSM example
aws cloudhsm create-hsm --cluster-id <cluster-id> \
  --availability-zone <az>

# Azure Key Vault
az keyvault certificate create \
  --vault-name MyKeyVault \
  --name CodeSignCert \
  --policy @policy.json
```

#### USB Token

- YubiKey 5 Series
- SafeNet eToken
- Thales SafeSign
- DigiCert ONE

## Platform-Specific Signing

### Windows (Authenticode)

#### Sign with SignTool

```powershell
# Sign executable
signtool sign /f codesign.pfx /p password /fd SHA256 \
  /t http://timestamp.digicert.com application.exe

# Sign with EV certificate (USB token)
signtool sign /n "Company Name" /fd SHA256 \
  /tr http://timestamp.digicert.com /td SHA256 \
  application.exe

# Sign multiple files
signtool sign /f codesign.pfx /p password /fd SHA256 \
  /t http://timestamp.digicert.com *.exe *.dll

# Verify signature
signtool verify /pa /v application.exe
```

#### Sign with osslsigncode (Linux)

```bash
# Install osslsigncode
sudo apt install osslsigncode

# Sign executable
osslsigncode sign -certs codesign.crt -key codesign.key \
  -t http://timestamp.digicert.com \
  -in application.exe -out application-signed.exe

# Sign with PKCS#12
osslsigncode sign -pkcs12 codesign.pfx -pass password \
  -t http://timestamp.digicert.com \
  -in application.exe -out application-signed.exe

# Verify
osslsigncode verify -in application-signed.exe
```

#### PowerShell Scripts

```powershell
# Sign PowerShell script
Set-AuthenticodeSignature -FilePath script.ps1 \
  -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)

# Verify signature
Get-AuthenticodeSignature script.ps1

# Set execution policy
Set-ExecutionPolicy AllSigned -Scope CurrentUser
```

#### MSI Installers

```powershell
# Sign MSI package
signtool sign /f codesign.pfx /p password /fd SHA256 \
  /t http://timestamp.digicert.com installer.msi

# Sign with dual signature (SHA1 + SHA256)
signtool sign /f codesign.pfx /p password /fd SHA1 \
  /t http://timestamp.digicert.com installer.msi
signtool sign /f codesign.pfx /p password /fd SHA256 /as \
  /tr http://timestamp.digicert.com /td SHA256 installer.msi
```

### macOS

#### Developer ID Application

```bash
# List available identities
security find-identity -v -p codesigning

# Sign application
codesign --sign "Developer ID Application: Company Name" \
  --timestamp --options runtime \
  --entitlements app.entitlements \
  --deep --force MyApp.app

# Verify signature
codesign --verify --deep --strict --verbose=2 MyApp.app
spctl --assess --verbose MyApp.app

# Display signature information
codesign -dv --verbose=4 MyApp.app
```

#### Notarization

```bash
# Create app-specific password
# Visit: https://appleid.apple.com/account/manage

# Store credentials
xcrun notarytool store-credentials "notary-profile" \
  --apple-id "developer@example.com" \
  --team-id "TEAM_ID" \
  --password "app-specific-password"

# Create distributable package
ditto -c -k --keepParent MyApp.app MyApp.zip

# Submit for notarization
xcrun notarytool submit MyApp.zip \
  --keychain-profile "notary-profile" \
  --wait

# Check notarization status
xcrun notarytool info <submission-id> \
  --keychain-profile "notary-profile"

# Staple notarization ticket
xcrun stapler staple MyApp.app

# Verify notarization
xcrun stapler validate MyApp.app
spctl -a -vvv -t install MyApp.app
```

#### Entitlements File

```xml
<!-- app.entitlements -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key>
    <true/>
</dict>
</plist>
```

#### Sign Installer Packages

```bash
# Build installer package
pkgbuild --root ./build --identifier com.company.app \
  --version 1.0 --install-location /Applications MyApp.pkg

# Sign package
productsign --sign "Developer ID Installer: Company Name" \
  MyApp.pkg MyApp-signed.pkg

# Verify
pkgutil --check-signature MyApp-signed.pkg
spctl -a -vvv -t install MyApp-signed.pkg
```

### Linux

#### AppImage

```bash
# Sign AppImage
gpg --detach-sign --armor MyApp.AppImage

# Verify
gpg --verify MyApp.AppImage.asc MyApp.AppImage
```

#### RPM Packages

```bash
# Generate GPG key for signing
gpg --gen-key

# Configure RPM signing
echo "%_gpg_name Your Name <email@example.com>" >> ~/.rpmmacros

# Sign RPM
rpm --addsign package.rpm

# Import public key
rpm --import public_key.asc

# Verify signature
rpm --checksig package.rpm
```

#### DEB Packages

```bash
# Sign with dpkg-sig
dpkg-sig --sign builder package.deb

# Verify
dpkg-sig --verify package.deb

# Sign repository metadata
gpg --clearsign InRelease
```

### Android

#### APK Signing

```bash
# Generate keystore
keytool -genkey -v -keystore release.keystore \
  -alias my-key-alias -keyalg RSA -keysize 3072 \
  -validity 10000

# Sign APK (v1 + v2 + v3)
apksigner sign --ks release.keystore \
  --ks-key-alias my-key-alias \
  --out app-signed.apk app-unsigned.apk

# Verify signature
apksigner verify --verbose app-signed.apk

# Display certificate
keytool -list -v -keystore release.keystore
```

#### AAB (Android App Bundle)

```bash
# Sign AAB
jarsigner -verbose -sigalg SHA256withRSA \
  -digestalg SHA-256 -keystore release.keystore \
  app-release.aab my-key-alias

# Verify
jarsigner -verify -verbose -certs app-release.aab
```

### iOS

```bash
# Configure Xcode code signing
# 1. Create App ID in Apple Developer Portal
# 2. Generate provisioning profile
# 3. Configure in Xcode: Signing & Capabilities

# Manual signing (if needed)
codesign --sign "iPhone Developer: Name (ID)" \
  --entitlements App.entitlements \
  MyApp.app

# Verify
codesign -dv --verbose=4 MyApp.app
```

### Docker Images

#### Docker Content Trust

```bash
# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Push signed image
docker push myregistry/myimage:tag

# Pull and verify signed image
docker pull myregistry/myimage:tag
```

#### Notary (Advanced)

```bash
# Initialize repository
notary init myregistry/myimage

# Add signature
notary add myregistry/myimage latest <sha256>

# Publish
notary publish myregistry/myimage

# Verify
notary list myregistry/myimage
```

#### Cosign (Sigstore)

```bash
# Install cosign
brew install cosign  # or download from GitHub

# Generate key pair
cosign generate-key-pair

# Sign container image
cosign sign --key cosign.key myregistry/myimage:tag

# Sign with keyless (OIDC)
cosign sign myregistry/myimage:tag

# Verify signature
cosign verify --key cosign.pub myregistry/myimage:tag

# Attach signature to image
cosign attach signature --signature sig.json myregistry/myimage:tag
```

## Timestamping

Timestamping ensures signatures remain valid after certificate expiration.

### Why Timestamp?

- Proves code was signed when certificate was valid
- Allows signature verification after certificate expires
- Required for long-term software validity

### Timestamp Authorities

```
DigiCert:      http://timestamp.digicert.com
Sectigo:       http://timestamp.sectigo.com
GlobalSign:    http://timestamp.globalsign.com
RFC 3161:      Use /tr flag with /td SHA256
```

### Timestamping Examples

```powershell
# Windows - Old timestamp (SHA1, deprecated)
signtool sign /f cert.pfx /p password /fd SHA256 \
  /t http://timestamp.digicert.com app.exe

# Windows - RFC 3161 timestamp (recommended)
signtool sign /f cert.pfx /p password /fd SHA256 \
  /tr http://timestamp.digicert.com /td SHA256 app.exe

# macOS
codesign --sign "Developer ID" --timestamp MyApp.app

# Linux (osslsigncode)
osslsigncode sign -pkcs12 cert.pfx -pass password \
  -ts http://timestamp.digicert.com \
  -in app.exe -out app-signed.exe
```

## Security Best Practices

### Private Key Protection

#### Store Keys Securely

```bash
# Use strong permissions
chmod 600 codesign.key
chown $(whoami):$(whoami) codesign.key

# Encrypt private key
openssl rsa -aes256 -in codesign.key -out codesign-encrypted.key

# Use HSM or hardware token for production
# Never commit keys to version control
```

#### .gitignore

```
# Add to .gitignore
*.pfx
*.p12
*.key
*.keystore
codesign.*
signing-key*
```

### Signing Process Security

#### Automated Signing Pipeline

```yaml
# GitHub Actions example
name: Sign and Release

on:
  push:
    tags:
      - 'v*'

jobs:
  sign:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build application
        run: dotnet build -c Release
      
      - name: Import certificate
        run: |
          $cert = [Convert]::FromBase64String("${{ secrets.SIGNING_CERT }}")
          [IO.File]::WriteAllBytes("cert.pfx", $cert)
      
      - name: Sign executable
        run: |
          signtool sign /f cert.pfx /p "${{ secrets.CERT_PASSWORD }}" `
            /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
            bin/Release/app.exe
      
      - name: Clean up certificate
        run: Remove-Item cert.pfx
```

### Certificate Lifecycle

#### Certificate Renewal

```bash
# Check expiration
openssl x509 -enddate -noout -in cert.crt

# Renew before expiration (typically 30-60 days)
# Re-sign all distributed software after renewal
```

#### Certificate Revocation

```bash
# Revoke compromised certificate
# Contact CA immediately
# Re-sign all software with new certificate
# Notify users to update
```

### Build Reproducibility

```bash
# Use deterministic builds
go build -trimpath -ldflags "-buildid=" main.go

# Sign reproducible artifacts
sha256sum binary.exe > checksums.txt
gpg --detach-sign --armor checksums.txt
```

## Verification and Validation

### Windows Verification

```powershell
# GUI verification
# Right-click file > Properties > Digital Signatures

# Command-line verification
signtool verify /pa /v application.exe

# Check SmartScreen reputation
# Run application, check for SmartScreen warnings

# Detailed certificate info
Get-AuthenticodeSignature application.exe | Format-List *
```

### macOS Verification

```bash
# Verify code signature
codesign --verify --deep --strict --verbose=2 MyApp.app

# Check Gatekeeper assessment
spctl --assess --verbose MyApp.app

# Display signature details
codesign -dv --verbose=4 MyApp.app

# Check notarization
spctl -a -vvv -t install MyApp.app
xcrun stapler validate MyApp.app
```

### Linux Verification

```bash
# GPG verification
gpg --verify signature.asc file

# RPM verification
rpm --checksig package.rpm

# DEB verification
dpkg-sig --verify package.deb
```

### Android Verification

```bash
# Verify APK signature
apksigner verify --verbose app.apk

# Display certificate
keytool -printcert -jarfile app.apk
```

### Container Verification

```bash
# Docker Content Trust
export DOCKER_CONTENT_TRUST=1
docker pull myimage:tag  # Automatically verifies

# Cosign
cosign verify --key cosign.pub myregistry/myimage:tag

# Notary
notary list myregistry/myimage
```

## Troubleshooting

### Common Issues

#### "Unknown Publisher" Warning (Windows)

**Causes:**
- Certificate not trusted in user's store
- New certificate without SmartScreen reputation
- Certificate chain incomplete

**Solutions:**
```powershell
# Verify certificate chain
signtool verify /pa /v /debug application.exe

# Check SmartScreen status
# Build reputation by signing many files, downloads

# Use EV certificate for instant reputation
```

#### "Damaged Application" Error (macOS)

**Causes:**
- Application not notarized
- Quarantine attribute set
- Signature invalid

**Solutions:**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine MyApp.app

# Verify and fix signature
codesign --verify --deep --strict --verbose=2 MyApp.app
codesign --force --sign "Developer ID" --deep MyApp.app

# Submit for notarization
xcrun notarytool submit MyApp.zip --keychain-profile "profile"
```

#### Signature Verification Failed

**Causes:**
- Certificate expired
- No timestamp
- File modified after signing
- Certificate chain broken

**Solutions:**
```bash
# Re-sign with timestamp
signtool sign /fd SHA256 /tr http://timestamp.digicert.com app.exe

# Verify certificate chain
openssl verify -CAfile chain.crt cert.crt

# Check file integrity
sha256sum original.exe signed.exe
```

#### Key Not Found

**Causes:**
- Wrong certificate store
- USB token not connected
- HSM not configured

**Solutions:**
```powershell
# List available certificates
certutil -store My

# Import certificate
certutil -f -user -p password -importpfx cert.pfx

# Check USB token
certutil -scinfo
```

## Additional Resources

- [Microsoft Code Signing Best Practices](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools)
- [Apple Code Signing Guide](https://developer.apple.com/support/code-signing/)
- [Android App Signing](https://developer.android.com/studio/publish/app-signing)
- [Sigstore Project](https://www.sigstore.dev/)
- [NIST SP 800-147 - BIOS Protection Guidelines](https://csrc.nist.gov/publications/detail/sp/800-147/final)

