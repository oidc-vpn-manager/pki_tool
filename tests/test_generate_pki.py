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
        ['generate-root', '--out-dir', str(output_dir)],
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
        ['generate-root', '--out-dir', str(output_dir)],
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
            '--out-dir', str(output_dir)
        ],
        input=intermediate_input_data
    )
    
    assert result.exit_code == 0
    assert "Success! Intermediate CA created." in result.output
    assert os.path.exists(output_dir / "intermediate-ca.key")

def test_overwrite_protection(runner, tmp_path):
    """
    Tests that the script aborts if files exist and the user declines to overwrite.
    """
    output_dir = tmp_path / "pki"
    output_dir.mkdir()
    (output_dir / "root-ca.key").touch() # Create a dummy file

    # The input 'N' should cause the script to abort
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir)],
        input="N\n"
    )

    assert result.exit_code == 1
    assert "Aborted!" in result.output

def test_pki_tool_error_handling(runner, tmp_path):
    """
    Tests various error conditions in the PKI tool.
    """
    output_dir = tmp_path / "pki"

    # Test 1: Unsupported key type for root generation
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--key-type', 'dsa'],
        input="some\ninput\n"
    )
    assert result.exit_code != 0
    assert "Invalid value for '--key-type'" in result.output

    # Test 2: Generate a root CA with an RSA key to test the next step
    result = runner.invoke(
        cli,
        ['generate-root', '--out-dir', str(output_dir), '--key-type', 'rsa2048'],
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
            '--out-dir', str(output_dir)
        ],
        input=intermediate_input_data
    )
    assert result.exit_code == 0
    assert "Writing rsa2048 private key" in result.output