import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from click.testing import CliRunner
from generate_pki import cli

intermediate_input_data = "\n".join(
    [
        "root-password", # Root passphrase (or repeat for the root generate)
        "", # Default subject fields (Country)
        "", # Default subject fields (State)
        "", # Default subject fields (Locality)
        "", # Default subject fields (Organization)
        "Intermediate CA", # New CN
        "intermediate-password", # Intermediate passphrase
        "intermediate-password" # Repeated Intermediate Passphrase
    ]
)

root_and_intermediate_input_data = "\n".join(
    [
        "GB",  # Country
        "Test State",  # State
        "Test City",  # Locality
        "Test Root Org",  # Organization
        "Test Root CA",  # Common Name
        "root-password",  # Root Passphrase
        intermediate_input_data
    ]
)

@pytest.fixture
def runner():
    """Provides a Click CLI runner for the tests."""
    return CliRunner()

def test_generate_root_and_intermediate(tmp_path):
    """
    Tests the full PKI generation process.
    """
    runner = CliRunner()
    output_dir = tmp_path / "pki"

    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--skip-entropy-validation'],
        input=root_and_intermediate_input_data
    )

    # Assert that the script ran successfully
    assert result.exit_code == 0
    assert "PKI Generation Complete" in result.output

    # Assert that the files were created
    assert os.path.exists(output_dir / "root-ca.key")
    assert os.path.exists(output_dir / "root-ca.crt")
    assert os.path.exists(output_dir / "intermediate-ca.key")
    assert os.path.exists(output_dir / "intermediate-ca.crt")

def test_generate_intermediate_standalone(runner, tmp_path):
    """
    Tests the 'generate-intermediate' command using existing root files.
    """
    output_dir = tmp_path / "pki"
    
    # --- First, create a root CA to sign with ---
    runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--skip-entropy-validation'],
        input=root_and_intermediate_input_data
    )
    
    # Delete the generated intermediate files so we can re-create them
    os.remove(output_dir / "intermediate-ca.key")
    os.remove(output_dir / "intermediate-ca.crt")
    
    # --- Now, run the standalone intermediate generation ---
    result = runner.invoke(
        cli,
        [
            'generate-intermediate',
            '--root-ca-cert', str(output_dir / "root-ca.crt"),
            '--root-ca-key', str(output_dir / "root-ca.key"),
            '--out-dir', str(output_dir),
            '--skip-entropy-validation'
        ],
        input=intermediate_input_data
    )
    
    assert result.exit_code == 0
    assert "Success! Intermediate CA created." in result.output
    assert os.path.exists(output_dir / "intermediate-ca.key")

def test_overwrite_protection(runner, tmp_path):
    """
    Tests that the script raises exception if root CA files already exist.
    """
    output_dir = tmp_path / "pki"
    output_dir.mkdir()
    (output_dir / "root-ca.key").touch() # Create a dummy file

    # Should raise exception when root CA files exist (no input needed)
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--skip-entropy-validation']
    )

    assert result.exit_code == 1
    assert result.exception is not None

def test_pki_tool_error_handling(runner, tmp_path):
    """
    Tests various error conditions in the PKI tool.
    """
    output_dir = tmp_path / "pki"

    # Test 1: Unsupported key type for root generation
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--key-type', 'dsa', '--skip-entropy-validation'],
        input="some\ninput\n"
    )
    assert result.exit_code != 0
    assert "Invalid value for '--key-type'" in result.output

    # Test 2: Generate a root CA with an RSA key to test the next step
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--key-type', 'rsa2048', '--skip-entropy-validation'],
        input=root_and_intermediate_input_data
    )
    # Check that the first part succeeded before proceeding
    assert result.exit_code == 0
    
    os.remove(output_dir / "intermediate-ca.key")
    os.remove(output_dir / "intermediate-ca.crt")
    
    # Test 3: Standalone intermediate generation with an RSA root
    # This covers the logic that infers the key type from the loaded root key.
    result = runner.invoke(
        cli,
        [
            'generate-intermediate',
            '--root-ca-cert', str(output_dir / "root-ca.crt"),
            '--root-ca-key', str(output_dir / "root-ca.key"),
            '--out-dir', str(output_dir),
            '--skip-entropy-validation'
        ],
        input=intermediate_input_data
    )
    assert result.exit_code == 0
    assert "Writing rsa2048 private key" in result.output

def test_intermediate_ca_files_exist_protection(runner, tmp_path):
    """
    Tests that the script raises exception if intermediate CA files already exist.
    """
    output_dir = tmp_path / "pki"
    output_dir.mkdir()

    # First create a root CA
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--key-type', 'ed25519', '--skip-entropy-validation'],
        input=root_and_intermediate_input_data
    )
    assert result.exit_code == 0

    # Now create dummy intermediate files to trigger the protection
    (output_dir / "intermediate-ca.key").touch()

    # Try to generate intermediate again - should raise exception before asking for input
    result = runner.invoke(
        cli,
        [
            'generate-intermediate',
            '--root-ca-cert', str(output_dir / "root-ca.crt"),
            '--root-ca-key', str(output_dir / "root-ca.key"),
            '--out-dir', str(output_dir),
            '--skip-entropy-validation'
        ],
        input="root-password\n"  # Just in case it gets to password prompt
    )

    assert result.exit_code == 1
    assert result.exception is not None

def test_unsupported_key_type_in_create_private_key(tmp_path):
    """
    Tests that create_private_key raises exception for unsupported key types.
    """
    from generate_pki import create_private_key
    import pytest

    key_path = tmp_path / "test.key"

    # Test unsupported key type like DSA
    with pytest.raises(Exception) as excinfo:
        create_private_key(str(key_path), "test-passphrase", "dsa", skip_entropy_validation=True)

    assert "Unsupported key type 'dsa'" in str(excinfo.value)


def test_create_private_key_entropy_validation_failure(tmp_path):
    """Test entropy validation failure in create_private_key - covers lines 34-36."""
    from generate_pki import create_private_key
    from unittest.mock import patch
    import click

    key_path = tmp_path / "test-key.pem"

    # Mock entropy validation to fail
    with patch('generate_pki.validate_entropy_for_key_generation', return_value=False):
        with pytest.raises(click.ClickException) as excinfo:
            create_private_key(str(key_path), "test-passphrase", "ed25519", skip_entropy_validation=False)

        assert "Entropy validation failed. Key generation aborted for security." in str(excinfo.value)