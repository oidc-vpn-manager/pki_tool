#!/usr/bin/env python3
"""
A standalone CLI tool for generating the Root and Intermediate CAs.
"""

import click
import os
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

# --- Helper Functions ---

def prompt_for_subject_fields(defaults=None):
    """Prompts the user for the components of a certificate's subject name."""
    defaults = defaults or {}
    return {
        "country": click.prompt("Country Name (2 letter code)", default=defaults.get("C", "GB")),
        "state": click.prompt("State or Province Name", default=defaults.get("ST", "England")),
        "locality": click.prompt("Locality Name (eg, city)", default=defaults.get("L", "London")),
        "organization": click.prompt("Organization Name", default=defaults.get("O", "OpenVPN Service")),
        "common_name": click.prompt("Common Name (e.g., FQDN)", default=defaults.get("CN")),
    }

def create_private_key(key_path, passphrase, key_type='ed25519'):
    """Generates and saves an encrypted private key."""
    if key_type == 'ed25519':
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type in ['rsa2048', 'rsa4096']:
        key_size = 4096 if key_type == 'rsa4096' else 2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    else:
        raise click.BadParameter(f"Unsupported key type '{key_type}'.") # pragma: no cover

    click.echo(f"  -> Writing {key_type} private key to {key_path}")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ))
    
    os.chmod(key_path, 0o600)
    return private_key

def get_signing_algorithm(private_key):
    """Determines the appropriate hash algorithm based on the key type."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        return hashes.SHA256()
    return None

def build_subject_name(fields):
    """Builds an x509.Name object from a dictionary of fields."""
    return x509.Name([
        x509.NameAttribute(oid, value) for oid, value in {
            NameOID.COUNTRY_NAME: fields["country"],
            NameOID.STATE_OR_PROVINCE_NAME: fields["state"],
            NameOID.LOCALITY_NAME: fields["locality"],
            NameOID.ORGANIZATION_NAME: fields["organization"],
            NameOID.COMMON_NAME: fields["common_name"],
        }.items() if value
    ])

def _generate_intermediate(root_cert, root_ca_key, out_dir, lifespan_years, key_type):
    """Shared logic to generate an intermediate CA."""
    click.secho("\n--- Generating a new Intermediate CA ---", bold=True)
    int_key_path = os.path.join(out_dir, 'intermediate-ca.key')
    int_cert_path = os.path.join(out_dir, 'intermediate-ca.crt')

    if os.path.exists(int_key_path) or os.path.exists(int_cert_path):
        click.confirm(f"Intermediate CA files already exist in {out_dir}. Overwrite?", abort=True) # pragma: no cover

    # Correct way to extract attributes from the subject
    defaults = {
        "C": root_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value,
        "ST": root_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value,
        "L": root_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value,
        "O": root_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
    }
    int_subject_fields = prompt_for_subject_fields(defaults=defaults)
    
    intermediate_passphrase = click.prompt("Enter a new passphrase for the Intermediate CA private key", hide_input=True, confirmation_prompt=True)
    intermediate_key = create_private_key(int_key_path, intermediate_passphrase, key_type)
    intermediate_subject = build_subject_name(int_subject_fields)

    intermediate_cert = x509.CertificateBuilder().subject_name(
        intermediate_subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        intermediate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=lifespan_years * 365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).add_extension(
        x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True
    ).sign(root_ca_key, get_signing_algorithm(root_ca_key))

    click.echo(f"  -> Writing certificate to {int_cert_path}")
    with open(int_cert_path, "wb") as f:
        f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
    
    click.secho("\nSuccess! Intermediate CA created.", fg="green")

# --- Click CLI Commands ---

@click.group()
def cli():
    """A tool to generate Root and Intermediate PKI for the VPN service."""
    pass

@cli.command()
@click.option('--out-dir', default='./pki', help='Directory to save the generated files.')
@click.option('--root-lifespan', default=30, type=int, help='Lifespan of the Root CA in years.')
@click.option('--intermediate-lifespan', default=10, type=int, help='Lifespan of the Intermediate CA in years.')
@click.option('--key-type', default='ed25519', type=click.Choice(['ed25519', 'rsa2048', 'rsa4096']), help='The type of private key to generate.')
def generate_root(out_dir, root_lifespan, intermediate_lifespan, key_type):
    """Generates a new Root CA and its first Intermediate CA."""
    
    click.secho("--- Generating a new Root CA ---", bold=True)
    os.makedirs(out_dir, exist_ok=True)
    root_key_path = os.path.join(out_dir, 'root-ca.key')
    root_cert_path = os.path.join(out_dir, 'root-ca.crt')

    if os.path.exists(root_key_path) or os.path.exists(root_cert_path):
        click.confirm(f"Root CA files already exist in {out_dir}. Overwrite?", abort=True)

    root_subject_fields = prompt_for_subject_fields()
    root_passphrase = click.prompt("Enter a new passphrase for the Root CA private key", hide_input=True, confirmation_prompt=True)
    root_key = create_private_key(root_key_path, root_passphrase, key_type)
    root_subject = build_subject_name(root_subject_fields)
    
    builder = x509.CertificateBuilder().subject_name(
        root_subject
    ).issuer_name(
        root_subject
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=root_lifespan * 365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True
    ).add_extension(
        x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True
    )
    
    root_cert = builder.sign(root_key, get_signing_algorithm(root_key))
    
    click.echo(f"  -> Writing certificate to {root_cert_path}")
    with open(root_cert_path, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))

    click.secho("\nSuccess! Root CA created.", fg="green")
    
    _generate_intermediate(root_cert, root_key, out_dir, intermediate_lifespan, key_type)
    
    click.secho("\n--- PKI Generation Complete ---", bold=True)
    click.echo("IMPORTANT: Securely back up the root-ca.key file and its passphrase. It is not recoverable.")

@cli.command()
@click.option('--root-ca-cert', required=True, type=click.Path(exists=True), help='Path to the Root CA certificate file.')
@click.option('--root-ca-key', required=True, type=click.Path(exists=True), help='Path to the Root CA private key file.')
@click.option('--out-dir', default='./pki', help='Directory to save the new intermediate files.')
@click.option('--intermediate-lifespan', default=10, type=int, help='Lifespan of the Intermediate CA in years.')
def generate_intermediate(root_ca_cert, root_ca_key, out_dir, intermediate_lifespan):
    """Generates a new Intermediate CA signed by an existing Root CA."""
    
    root_ca_passphrase = click.prompt("Enter the passphrase for the Root CA private key", hide_input=True)
    with open(root_ca_key, "rb") as f:
        root_key = serialization.load_pem_private_key(f.read(), password=root_ca_passphrase.encode())
    with open(root_ca_cert, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
        
    if isinstance(root_key, rsa.RSAPrivateKey):
        key_type = 'rsa4096' if root_key.key_size == 4096 else 'rsa2048'
    else:
        key_type = 'ed25519'
    
    _generate_intermediate(root_cert, root_key, out_dir, intermediate_lifespan, key_type)

if __name__ == '__main__':
    cli() # pragma: no cover