# PKI Tool

This file provides LLMs with guidance for working with the PKI Tool component of OpenVPN Manager.

## Tool Overview

The PKI Tool is a command-line utility for generating Root and Intermediate Certificate Authorities (CAs) for OpenVPN Manager. It creates the foundational PKI materials needed to operate a secure OpenVPN certificate management system with modern cryptographic standards.

## Architecture

### File Structure
- `generate_pki.py` - Main executable script
- `tests/` - Comprehensive test suite
  - `test_generate_pki.py` - Unit and integration tests
  - `requirements.txt` - Test dependencies
- `requirements.txt` - Runtime dependencies
- `README.md` - Comprehensive usage documentation

### Core Components
- **Key Generation**: Support for Ed25519, RSA 2048/4096
- **Certificate Creation**: X.509v3 compliant certificates
- **Interactive Setup**: Guided configuration process
- **Security Features**: Encrypted private keys with passphrases

## Dependencies

### Runtime Requirements
- **cryptography**: Modern Python cryptographic operations
- **Python 3.8+**: Required for cryptography library features

### Testing Dependencies
- **pytest**: Test framework and runner
- **pytest-cov**: Coverage reporting
- **Additional test utilities**: As specified in `tests/requirements.txt`

## Development Workflow

### Local Development
```bash
cd tools/pki_tool

# Install runtime dependencies
pip install -r requirements.txt

# Install test dependencies
pip install -r tests/requirements.txt

# Make executable
chmod +x generate_pki.py

# Run basic generation
./generate_pki.py --output-dir ./test-pki
```

### Testing
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=generate_pki --cov-report=html

# Run specific test categories
python -m pytest tests/test_generate_pki.py::test_complete_workflow -v
python -m pytest tests/test_generate_pki.py::test_key_types -v
```

## Command-Line Interface

### Basic Usage
```bash
# Interactive mode with defaults
./generate_pki.py --output-dir /path/to/pki

# Specify key type
./generate_pki.py --output-dir /path/to/pki --key-type ed25519
./generate_pki.py --output-dir /path/to/pki --key-type rsa2048
./generate_pki.py --output-dir /path/to/pki --key-type rsa4096
```

### Advanced Configuration
```bash
# Non-interactive with full configuration
./generate_pki.py \
  --output-dir /secure/pki \
  --key-type ed25519 \
  --country US \
  --state California \
  --locality "San Francisco" \
  --organization "Example Corp" \
  --root-cn "Example Corp Root CA" \
  --intermediate-cn "Example Corp Intermediate CA" \
  --root-ca-days 3650 \
  --intermediate-ca-days 1095
```

### Command-Line Arguments
- `--output-dir` - Directory for generated files (required)
- `--key-type` - Key type: ed25519 (default), rsa2048, rsa4096
- `--country` - 2-letter country code (default: GB)
- `--state` - State or province name (default: England)
- `--locality` - City name (default: London)
- `--organization` - Organization name (default: OpenVPN Service)
- `--root-cn` - Root CA common name
- `--intermediate-cn` - Intermediate CA common name
- `--root-ca-days` - Root CA validity in days (default: 3650)
- `--intermediate-ca-days` - Intermediate CA validity in days (default: 1825)

## Generated PKI Structure

### Output Files
```
output-dir/
├── root-ca.crt          # Root CA certificate (public)
├── root-ca.key          # Root CA private key (encrypted)
├── intermediate-ca.crt  # Intermediate CA certificate (public)
└── intermediate-ca.key  # Intermediate CA private key (encrypted)
```

### File Permissions
- **Certificate files (*.crt)**: 644 (publicly readable)
- **Private key files (*.key)**: 600 (owner only)

### Certificate Properties
- **Root CA**: Self-signed, unlimited path length, 10-year validity
- **Intermediate CA**: Signed by root, path length 0, 5-year validity
- **Modern Extensions**: Proper X.509v3 extensions and constraints

## Cryptographic Standards

### Supported Key Types
- **Ed25519** (recommended): Modern elliptic curve, fast operations
- **RSA 2048**: Traditional RSA, broad compatibility
- **RSA 4096**: High security RSA, maximum protection

### Certificate Standards
- **X.509v3**: Modern certificate format
- **Proper Constraints**: CA:TRUE with appropriate path length
- **Key Usage**: Certificate signing, CRL signing
- **Secure Algorithms**: SHA-256 or better for signatures

## Security Features

### Private Key Protection
- **PKCS#8 Encryption**: All private keys encrypted with passphrases
- **Strong Passphrases**: Interactive entry with confirmation
- **Secure Generation**: High-entropy key generation
- **Memory Protection**: Secure handling during generation

### Operational Security
- **Offline Generation**: Designed for air-gapped systems
- **Secure Storage**: Guidance for proper key storage
- **Access Control**: File permission management
- **Audit Trail**: Generation logging and verification

## Testing Standards

### Test Coverage Requirements
- **100% code coverage**: All functions and branches tested
- **Cryptographic Validation**: Certificate and key validation tests
- **Error Handling**: Exception and error condition testing
- **Integration Tests**: Complete workflow validation

### Test Categories
- **Unit Tests**: Individual function testing
- **Integration Tests**: Complete PKI generation workflows
- **Security Tests**: Cryptographic validation and security checks
- **Compatibility Tests**: Different key types and configurations

## Integration with OpenVPN Manager

### Service Integration
```bash
# Copy PKI materials to services
cp output-dir/root-ca.crt services/frontend/pki/
cp output-dir/intermediate-ca.crt services/signing/pki/
cp output-dir/intermediate-ca.key services/signing/pki/

# Set up signing service
echo "passphrase-here" > services/signing/pki/ca_key_passphrase
chmod 600 services/signing/pki/ca_key_passphrase
```

### Docker Integration
```bash
# Create PKI volume
docker volume create openvpn-pki

# Copy materials to volume
docker run --rm -v openvpn-pki:/pki -v $(pwd)/output-dir:/source \
  busybox cp -r /source/* /pki/
```

### Kubernetes Integration
```bash
# Create secret with PKI materials
kubectl create secret generic openvpn-pki \
  --from-file=root-ca.crt=output-dir/root-ca.crt \
  --from-file=intermediate-ca.crt=output-dir/intermediate-ca.crt \
  --from-file=intermediate-ca.key=output-dir/intermediate-ca.key \
  -n openvpn-manager
```

## Common Operations

### Updating Certificate Generation
1. Modify certificate generation logic in main script
2. Update certificate extensions or validity periods
3. Add comprehensive tests for changes
4. Validate against existing PKI materials
5. Update documentation and examples

### Adding New Key Types
1. Extend key generation functions
2. Add command-line argument support
3. Implement certificate generation for new key type
4. Add comprehensive test coverage
5. Update CLI help and documentation

### Security Enhancements
1. Review cryptographic implementations
2. Update to latest security standards
3. Enhance passphrase handling
4. Improve secure memory operations
5. Add security-focused testing

## Debugging & Troubleshooting

### Common Issues
- **Permission Errors**: Check output directory permissions
- **Cryptography Errors**: Update cryptography library version
- **Passphrase Issues**: Ensure consistent passphrase entry
- **Certificate Validation**: Verify system time and dependencies

### Debug Features
- **Verbose Output**: Add detailed logging for operations
- **Certificate Inspection**: Use OpenSSL for validation
- **Key Testing**: Verify private key encryption and access
- **Chain Validation**: Test certificate trust chains

### Validation Commands
```bash
# Inspect generated certificates
openssl x509 -in root-ca.crt -text -noout
openssl x509 -in intermediate-ca.crt -text -noout

# Verify certificate chain
openssl verify -CAfile root-ca.crt intermediate-ca.crt

# Test private key encryption
openssl rsa -in root-ca.key -check -noout
openssl rsa -in intermediate-ca.key -check -noout
```

## Automation & Scripting

### Automated Generation Scripts
```bash
#!/bin/bash
# Automated PKI generation with validation

set -euo pipefail

OUTPUT_DIR="/secure/pki-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/pki-generation.log"

# Generate PKI
./generate_pki.py \
  --output-dir "$OUTPUT_DIR" \
  --key-type ed25519 \
  --organization "Your Organization" 2>&1 | tee "$LOG_FILE"

# Validate results
openssl verify -CAfile "$OUTPUT_DIR/root-ca.crt" "$OUTPUT_DIR/intermediate-ca.crt"

# Secure file permissions
chmod 600 "$OUTPUT_DIR"/*.key
chmod 644 "$OUTPUT_DIR"/*.crt

echo "PKI generation complete: $OUTPUT_DIR"
```

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
name: PKI Tool Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - run: pip install -r requirements.txt -r tests/requirements.txt
    - run: python -m pytest tests/ --cov=generate_pki --cov-report=xml
    - run: ./generate_pki.py --output-dir /tmp/test-pki --organization "CI Test"
```

## Performance Considerations

### Key Generation Performance
- **Ed25519**: Fastest key generation and operations
- **RSA 2048**: Moderate performance, good compatibility
- **RSA 4096**: Slower generation, maximum security

### System Requirements
- **CPU**: Modern processor for cryptographic operations
- **Memory**: Sufficient RAM for key generation (typically minimal)
- **Entropy**: Good system entropy source for key generation
- **Storage**: Secure storage for private key materials