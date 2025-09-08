# PKI Generation Tool

A command-line tool for generating Root and Intermediate Certificate Authorities (CAs) for OpenVPN Manager. This tool creates the foundational PKI materials needed to operate a secure OpenVPN certificate management system.

## 🔐 Security Architecture

The PKI tool implements industry-standard security practices:

- **Offline Root CA**: Root CA private key should be generated offline and stored securely
- **Intermediate CA**: Online intermediate CA for daily certificate signing operations
- **Modern Cryptography**: Support for Ed25519 (recommended) and RSA (2048/4096 bit) keys
- **Encrypted Private Keys**: All private keys are passphrase-protected using PKCS#8 encryption

## 🚀 Features

### Key Generation
- **Ed25519**: Modern, fast elliptic curve cryptography (recommended)
- **RSA 2048**: Traditional RSA with 2048-bit keys (broad compatibility)
- **RSA 4096**: High-security RSA with 4096-bit keys (maximum security)

### Certificate Authority Creation
- **Root CA**: Self-signed root certificate authority for trust anchor
- **Intermediate CA**: Intermediate certificate authority signed by root CA
- **Flexible Validity Periods**: Configurable certificate lifetimes
- **Standard X.509v3 Extensions**: Proper CA constraints and key usage flags

### Interactive Configuration
- **Subject Information**: Guided prompts for certificate subject fields
- **Passphrase Security**: Interactive passphrase entry with confirmation
- **File Organization**: Organized output directory structure

## 📦 Installation

### Prerequisites
- Python 3.8+
- `cryptography` library for certificate operations

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Make Executable
```bash
chmod +x generate_pki.py
```

## 💻 Usage

### Basic PKI Generation

Generate a complete PKI infrastructure with Ed25519 keys:

```bash
./generate_pki.py --output-dir ./pki
```

This creates:
```
pki/
├── root-ca.crt          # Root CA certificate
├── root-ca.key          # Root CA private key (encrypted)
├── intermediate-ca.crt  # Intermediate CA certificate  
└── intermediate-ca.key  # Intermediate CA private key (encrypted)
```

### Advanced Options

#### Specify Key Type
```bash
# Use Ed25519 keys (default, recommended)
./generate_pki.py --output-dir ./pki --key-type ed25519

# Use RSA 2048-bit keys for broader compatibility
./generate_pki.py --output-dir ./pki --key-type rsa2048

# Use RSA 4096-bit keys for maximum security
./generate_pki.py --output-dir ./pki --key-type rsa4096
```

#### Custom Validity Periods
```bash
# Root CA valid for 10 years, Intermediate for 3 years
./generate_pki.py --output-dir ./pki \
  --root-ca-days 3650 \
  --intermediate-ca-days 1095
```

#### Automated (Non-Interactive) Generation
```bash
# Pre-configure subject information
./generate_pki.py --output-dir ./pki \
  --country US \
  --state California \
  --locality "San Francisco" \
  --organization "Example Corp" \
  --root-cn "Example Corp Root CA" \
  --intermediate-cn "Example Corp Intermediate CA"
```

### Complete Example

```bash
#!/bin/bash
# Complete PKI generation script

OUTPUT_DIR="/secure/pki"
KEY_TYPE="ed25519"
COUNTRY="US"
STATE="California"
LOCALITY="San Francisco"  
ORGANIZATION="Example Corporation"

./generate_pki.py \
  --output-dir "$OUTPUT_DIR" \
  --key-type "$KEY_TYPE" \
  --country "$COUNTRY" \
  --state "$STATE" \
  --locality "$LOCALITY" \
  --organization "$ORGANIZATION" \
  --root-cn "Example Corp Root CA" \
  --intermediate-cn "Example Corp Intermediate CA" \
  --root-ca-days 3650 \
  --intermediate-ca-days 1095

# Secure the private keys
chmod 600 "$OUTPUT_DIR"/*.key
chown root:root "$OUTPUT_DIR"/*.key

echo "PKI generation complete. Root CA private key should be moved offline."
```

## 🔧 Configuration Options

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--output-dir` | Directory to store generated files | Required |
| `--key-type` | Key type: ed25519, rsa2048, rsa4096 | ed25519 |
| `--country` | Country code (2 letters) | GB |
| `--state` | State or province name | England |
| `--locality` | City or locality name | London |
| `--organization` | Organization name | OpenVPN Service |
| `--root-cn` | Root CA common name | [Organization] Root CA |
| `--intermediate-cn` | Intermediate CA common name | [Organization] Intermediate CA |
| `--root-ca-days` | Root CA validity period in days | 3650 (10 years) |
| `--intermediate-ca-days` | Intermediate CA validity period | 1825 (5 years) |

### Interactive Mode

When run without subject parameters, the tool prompts for:
- Country Name (2 letter code)
- State or Province Name
- Locality Name (city)
- Organization Name
- Common Name for Root CA
- Common Name for Intermediate CA
- Passphrase for Root CA private key
- Passphrase for Intermediate CA private key

## 🛡️ Security Best Practices

### Root CA Security
1. **Generate Offline**: Create root CA on an air-gapped system
2. **Secure Storage**: Store root CA private key on encrypted offline media
3. **Limited Access**: Restrict access to root CA materials to authorized personnel only
4. **Physical Security**: Use hardware security modules (HSM) or secure offline storage

### Intermediate CA Security
1. **Online Operations**: Intermediate CA can be used for daily signing operations
2. **Regular Backup**: Backup intermediate CA private key securely
3. **Access Control**: Limit access to signing service only
4. **Monitoring**: Monitor certificate issuance for anomalies

### Operational Security
1. **Strong Passphrases**: Use long, complex passphrases for private key encryption
2. **Key Rotation**: Plan for regular intermediate CA key rotation
3. **Certificate Transparency**: Log all issued certificates for audit purposes
4. **Disaster Recovery**: Maintain secure backups and recovery procedures

## 📁 Output Structure

### Generated Files

**Root CA Files**:
- `root-ca.crt`: Root CA certificate (public, distribute to clients)
- `root-ca.key`: Root CA private key (encrypted, keep offline)

**Intermediate CA Files**:
- `intermediate-ca.crt`: Intermediate CA certificate (public, used for trust chain)
- `intermediate-ca.key`: Intermediate CA private key (encrypted, used by signing service)

### File Permissions

The tool automatically sets secure file permissions:
- Certificate files (`.crt`): 644 (readable by all)
- Private key files (`.key`): 600 (readable by owner only)

### Certificate Properties

**Root CA Certificate**:
- Self-signed certificate authority
- Basic constraints: CA:TRUE, path length unlimited
- Key usage: Certificate signing, CRL signing
- 10-year default validity period

**Intermediate CA Certificate**:
- Signed by root CA
- Basic constraints: CA:TRUE, path length 0 (no sub-CAs)
- Key usage: Certificate signing, CRL signing
- 5-year default validity period

## 🧪 Testing

### Unit Tests
```bash
python -m pytest tests/ -v
```

### Integration Testing
```bash
# Test complete PKI generation workflow
python -m pytest tests/test_generate_pki.py::test_complete_workflow -v

# Test different key types
python -m pytest tests/test_generate_pki.py::test_key_types -v
```

### Manual Verification

Verify generated certificates:
```bash
# Inspect root CA certificate
openssl x509 -in pki/root-ca.crt -text -noout

# Inspect intermediate CA certificate  
openssl x509 -in pki/intermediate-ca.crt -text -noout

# Verify intermediate CA is signed by root CA
openssl verify -CAfile pki/root-ca.crt pki/intermediate-ca.crt

# Test private key encryption
openssl rsa -in pki/root-ca.key -check -noout
```

## 🔄 Integration with OpenVPN Manager

### Deployment Integration

Copy generated PKI materials to OpenVPN Manager:

```bash
# For Docker deployment
cp pki/root-ca.crt deploy/docker/pki/
cp pki/intermediate-ca.crt deploy/docker/pki/
cp pki/intermediate-ca.key deploy/docker/pki/

# For Kubernetes deployment
kubectl create secret generic openvpn-manager-pki \
  --from-file=root-ca.crt=pki/root-ca.crt \
  --from-file=intermediate-ca.crt=pki/intermediate-ca.crt \
  --from-file=intermediate-ca.key=pki/intermediate-ca.key \
  -n openvpn-manager
```

### Service Configuration

Configure OpenVPN Manager services to use the generated PKI:

```bash
# Frontend service environment
ROOT_CA_CERTIFICATE_FILE=/app/pki/root-ca.crt
INTERMEDIATE_CA_CERTIFICATE_FILE=/app/pki/intermediate-ca.crt

# Signing service environment
INTERMEDIATE_CA_CERTIFICATE_FILE=/pki/intermediate-ca.crt
INTERMEDIATE_CA_KEY_FILE=/pki/intermediate-ca.key
INTERMEDIATE_CA_KEY_PASSPHRASE_FILE=/run/secrets/ca_key_passphrase
```

## ❓ Troubleshooting

### Common Issues

**Permission Errors**:
- Ensure output directory is writable
- Check file system permissions and ownership
- Verify the tool runs with appropriate user privileges

**Cryptography Errors**:
- Update the `cryptography` library to the latest version
- Check Python version compatibility (3.8+ required)
- Verify system entropy for key generation

**Passphrase Issues**:
- Ensure consistent passphrase entry during generation
- Store passphrases securely in password manager
- Test private key decryption after generation

**Certificate Validation Errors**:
- Verify system time is correct
- Check certificate validity periods
- Ensure proper certificate chain construction

### Debug Mode

Enable verbose output:
```bash
./generate_pki.py --output-dir ./pki --verbose
```

## 🔮 Advanced Usage

### Custom Extensions

For advanced users needing custom certificate extensions, modify the certificate generation code to add:
- Custom subject alternative names
- Organization-specific policy OIDs
- Enhanced key usage restrictions
- Certificate transparency extensions

### Integration Scripting

Example automation script:
```bash
#!/bin/bash
# Automated PKI generation and deployment

set -euo pipefail

PKI_DIR="/tmp/pki-$(date +%Y%m%d)"
VAULT_PATH="secret/openvpn/pki"

# Generate PKI
./generate_pki.py \
  --output-dir "$PKI_DIR" \
  --key-type ed25519 \
  --organization "Example Corp" \
  --country US \
  --state California \
  --locality "San Francisco"

# Store in Vault
vault kv put "$VAULT_PATH" \
  root_ca_cert=@"$PKI_DIR/root-ca.crt" \
  intermediate_ca_cert=@"$PKI_DIR/intermediate-ca.crt" \
  intermediate_ca_key=@"$PKI_DIR/intermediate-ca.key"

# Secure cleanup
shred -vfz -n 3 "$PKI_DIR"/*.key
rm -rf "$PKI_DIR"

echo "PKI generated and stored securely in Vault"
```

## 🤝 Contributing

Contributions are welcome! Since this is Free Software:

- No copyright assignment needed, but will be gratefully received
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project
- Please ensure all tests pass and maintain code coverage
- Follow existing security practices and cryptographic standards

### Development Standards
- Comprehensive test coverage for all cryptographic operations
- Security-first design for key material handling
- Clear documentation for new key types or algorithms
- Compatibility with standard PKI tools and formats

## 📄 License

This software is released under the [GNU Affero General Public License version 3](LICENSE).

## 🤖 AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be rewritten to remove or properly credit any unlicensed or uncredited work.