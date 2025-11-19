import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, mock_open, MagicMock
import click
from entropy_validator import EntropyValidator, validate_entropy_for_key_generation


class TestEntropyValidator:
    """Tests for the EntropyValidator class."""

    def test_entropy_validator_init(self):
        """Test EntropyValidator initialization."""
        validator = EntropyValidator()
        assert validator.min_entropy_bytes == 512
        assert validator.min_entropy_quality == 0.7
        assert '/dev/random' in validator.entropy_sources
        assert '/dev/urandom' in validator.entropy_sources

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='2048\n')
    def test_check_system_entropy_sufficient(self, mock_file, mock_exists):
        """Test entropy check with sufficient entropy."""
        # Mock entropy sources exist
        mock_exists.side_effect = lambda path: path in ['/dev/random', '/dev/urandom', '/proc/sys/kernel/random/entropy_avail']

        validator = EntropyValidator()

        # Mock high-quality entropy test
        with patch.object(validator, '_test_entropy_quality', return_value=0.8):
            is_sufficient, info = validator.check_system_entropy()

        assert is_sufficient
        assert info['available_entropy'] == 2048
        assert info['entropy_quality'] == 0.8
        assert len(info['sources_available']) == 3

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data='100\n')
    def test_check_system_entropy_insufficient(self, mock_file, mock_exists):
        """Test entropy check with insufficient entropy."""
        # Mock limited entropy sources
        mock_exists.side_effect = lambda path: path == '/proc/sys/kernel/random/entropy_avail'

        validator = EntropyValidator()

        # Mock low-quality entropy test
        with patch.object(validator, '_test_entropy_quality', return_value=0.3):
            is_sufficient, info = validator.check_system_entropy()

        assert not is_sufficient
        assert info['available_entropy'] == 100
        assert info['entropy_quality'] == 0.3
        assert len(info['sources_available']) == 1
        assert len(info['recommendations']) > 0

    @patch('os.urandom')
    def test_entropy_quality_testing(self, mock_urandom):
        """Test entropy quality assessment."""
        # Generate predictable but varied data for testing
        test_data = bytes(range(256)) * 4  # 1024 bytes with good distribution
        mock_urandom.return_value = test_data

        validator = EntropyValidator()
        quality = validator._test_entropy_quality()

        # Should be reasonably high quality due to good byte distribution
        assert 0.0 <= quality <= 1.0
        mock_urandom.assert_called_once_with(1024)

    @patch('os.urandom')
    def test_entropy_quality_low_entropy(self, mock_urandom):
        """Test entropy quality with poor randomness."""
        # Generate highly repetitive data
        test_data = b'\x00' * 1024  # All zeros
        mock_urandom.return_value = test_data

        validator = EntropyValidator()
        quality = validator._test_entropy_quality()

        # Should be low quality due to no variation
        assert quality < 0.5

    @patch('os.urandom')
    def test_entropy_quality_exception_handling(self, mock_urandom):
        """Test entropy quality with os.urandom exception."""
        mock_urandom.side_effect = OSError("Entropy source unavailable")

        validator = EntropyValidator()
        quality = validator._test_entropy_quality()

        # Should return moderate quality on failure
        assert quality == 0.5

    def test_add_entropy_recommendations(self):
        """Test entropy recommendations generation."""
        validator = EntropyValidator()
        entropy_info = {
            'available_entropy': 100,
            'entropy_quality': 0.3,
            'sources_available': ['/dev/urandom'],
            'recommendations': []
        }

        validator._add_entropy_recommendations(entropy_info)

        recommendations = entropy_info['recommendations']
        assert len(recommendations) > 0
        assert any('Increase system entropy' in rec for rec in recommendations)
        assert any('Entropy quality below threshold' in rec for rec in recommendations)
        assert any('Limited entropy sources' in rec for rec in recommendations)

    @patch('time.time')
    @patch('time.sleep')
    @patch('click.echo')
    def test_wait_for_entropy_success(self, mock_echo, mock_sleep, mock_time):
        """Test waiting for entropy improvement."""
        validator = EntropyValidator()

        # Mock time progression - need enough values for the loop
        mock_time.side_effect = [0, 5, 10, 15]  # Start, check, loop, success

        # Mock entropy check improving over time
        with patch.object(validator, 'check_system_entropy', side_effect=[
            (False, {}),  # First check fails
            (True, {})    # Second check succeeds
        ]):
            result = validator.wait_for_entropy(timeout=60)

        assert result is True

    @patch('time.time')
    @patch('time.sleep')
    @patch('click.echo')
    def test_wait_for_entropy_timeout(self, mock_echo, mock_sleep, mock_time):
        """Test waiting for entropy with timeout."""
        validator = EntropyValidator()

        # Mock time progression past timeout - provide many values
        mock_time.side_effect = [0] + list(range(1, 70))  # Start, then incremental time values

        # Mock entropy check always failing
        with patch.object(validator, 'check_system_entropy', return_value=(False, {})):
            result = validator.wait_for_entropy(timeout=60)

        assert result is False

    def test_generate_entropy_report_sufficient(self):
        """Test entropy report generation with sufficient entropy."""
        validator = EntropyValidator()

        with patch.object(validator, 'check_system_entropy', return_value=(
            True, {
                'available_entropy': 2048,
                'entropy_quality': 0.85,
                'sources_available': ['/dev/random', '/dev/urandom'],
                'warnings': [],
                'recommendations': []
            }
        )):
            report = validator.generate_entropy_report()

        assert '✓ SUFFICIENT' in report
        assert '2048 bytes' in report
        assert '0.85' in report

    def test_generate_entropy_report_insufficient(self):
        """Test entropy report generation with insufficient entropy."""
        validator = EntropyValidator()

        with patch.object(validator, 'check_system_entropy', return_value=(
            False, {
                'available_entropy': 100,
                'entropy_quality': 0.3,
                'sources_available': ['/dev/urandom'],
                'warnings': ['Low entropy warning'],
                'recommendations': ['Install haveged', 'Use hardware RNG']
            }
        )):
            report = validator.generate_entropy_report()

        assert '✗ INSUFFICIENT' in report
        assert '100 bytes' in report
        assert '0.30' in report
        assert 'Warnings:' in report
        assert 'Recommendations:' in report


class TestValidateEntropyForKeyGeneration:
    """Tests for the entropy validation function."""

    @patch('entropy_validator.EntropyValidator')
    def test_entropy_validation_sufficient_ed25519(self, mock_validator_class):
        """Test entropy validation for Ed25519 key generation."""
        # Mock validator instance
        mock_validator = MagicMock()
        mock_validator.min_entropy_bytes = 512
        mock_validator.check_system_entropy.return_value = (True, {})
        mock_validator_class.return_value = mock_validator

        result = validate_entropy_for_key_generation('ed25519', interactive=False)

        assert result is True
        assert mock_validator.min_entropy_bytes == 512  # Ed25519 requirement

    @patch('entropy_validator.EntropyValidator')
    def test_entropy_validation_sufficient_rsa4096(self, mock_validator_class):
        """Test entropy validation for RSA 4096 key generation."""
        mock_validator = MagicMock()
        mock_validator.min_entropy_bytes = 1024
        mock_validator.check_system_entropy.return_value = (True, {})
        mock_validator_class.return_value = mock_validator

        result = validate_entropy_for_key_generation('rsa4096', interactive=False)

        assert result is True
        assert mock_validator.min_entropy_bytes == 1024  # RSA 4096 requirement

    @patch('entropy_validator.EntropyValidator')
    def test_entropy_validation_insufficient_non_interactive(self, mock_validator_class):
        """Test entropy validation failure in non-interactive mode."""
        mock_validator = MagicMock()
        mock_validator.check_system_entropy.return_value = (False, {})
        mock_validator.generate_entropy_report.return_value = "Mock entropy report"
        mock_validator_class.return_value = mock_validator

        result = validate_entropy_for_key_generation('ed25519', interactive=False)

        assert result is False

    @patch('entropy_validator.EntropyValidator')
    @patch('click.echo')
    @patch('click.secho')
    @patch('click.prompt')
    def test_entropy_validation_interactive_wait_success(self, mock_prompt, mock_secho, mock_echo, mock_validator_class):
        """Test interactive entropy validation with wait option."""
        mock_validator = MagicMock()
        mock_validator.check_system_entropy.return_value = (False, {})
        mock_validator.generate_entropy_report.return_value = "Mock entropy report"
        mock_validator.wait_for_entropy.return_value = True
        mock_validator_class.return_value = mock_validator

        # User chooses option 1 (wait)
        mock_prompt.return_value = 1

        result = validate_entropy_for_key_generation('ed25519', interactive=True)

        assert result is True
        mock_validator.wait_for_entropy.assert_called_once()

    @patch('entropy_validator.EntropyValidator')
    @patch('click.echo')
    @patch('click.secho')
    @patch('click.prompt')
    def test_entropy_validation_interactive_continue_anyway(self, mock_prompt, mock_secho, mock_echo, mock_validator_class):
        """Test interactive entropy validation with continue option."""
        mock_validator = MagicMock()
        mock_validator.check_system_entropy.return_value = (False, {})
        mock_validator.generate_entropy_report.return_value = "Mock entropy report"
        mock_validator_class.return_value = mock_validator

        # User chooses option 2 (continue anyway)
        mock_prompt.return_value = 2

        result = validate_entropy_for_key_generation('ed25519', interactive=True)

        assert result is True

    @patch('entropy_validator.EntropyValidator')
    @patch('click.echo')
    @patch('click.secho')
    @patch('click.prompt')
    def test_entropy_validation_interactive_abort(self, mock_prompt, mock_secho, mock_echo, mock_validator_class):
        """Test interactive entropy validation with abort option."""
        mock_validator = MagicMock()
        mock_validator.check_system_entropy.return_value = (False, {})
        mock_validator.generate_entropy_report.return_value = "Mock entropy report"
        mock_validator_class.return_value = mock_validator

        # User chooses option 3 (abort)
        mock_prompt.return_value = 3

        result = validate_entropy_for_key_generation('ed25519', interactive=True)

        assert result is False

    @patch('entropy_validator.EntropyValidator')
    @patch('click.echo')
    @patch('click.secho')
    @patch('click.prompt')
    def test_entropy_validation_interactive_wait_timeout(self, mock_prompt, mock_secho, mock_echo, mock_validator_class):
        """Test interactive entropy validation with wait timeout."""
        mock_validator = MagicMock()
        mock_validator.check_system_entropy.return_value = (False, {})
        mock_validator.generate_entropy_report.return_value = "Mock entropy report"
        mock_validator.wait_for_entropy.return_value = False  # Timeout
        mock_validator_class.return_value = mock_validator

        # User chooses option 1 (wait)
        mock_prompt.return_value = 1

        result = validate_entropy_for_key_generation('ed25519', interactive=True)

        assert result is False


class TestEntropyValidatorEdgeCases:
    """Test edge cases and error conditions."""

    @patch('os.path.exists', return_value=False)
    def test_no_entropy_sources_available(self, mock_exists):
        """Test entropy check with no sources available."""
        validator = EntropyValidator()
        is_sufficient, info = validator.check_system_entropy()

        assert not is_sufficient
        assert info['available_entropy'] == 0
        assert len(info['sources_available']) == 0

    @patch('os.path.exists')
    @patch('builtins.open', side_effect=IOError("Permission denied"))
    def test_entropy_avail_read_error(self, mock_file, mock_exists):
        """Test entropy check with file read error."""
        mock_exists.return_value = True

        validator = EntropyValidator()
        is_sufficient, info = validator.check_system_entropy()

        assert len(info['warnings']) > 0
        assert any('Could not read entropy_avail' in w for w in info['warnings'])

    def test_entropy_requirements_by_key_type(self):
        """Test different entropy requirements for different key types."""
        with patch('entropy_validator.EntropyValidator') as mock_validator_class:
            mock_validator = MagicMock()
            mock_validator.check_system_entropy.return_value = (True, {})
            mock_validator_class.return_value = mock_validator

            # Test Ed25519
            validate_entropy_for_key_generation('ed25519', interactive=False)
            assert mock_validator.min_entropy_bytes == 512

            # Test RSA 2048
            mock_validator.min_entropy_bytes = 512  # Reset
            validate_entropy_for_key_generation('rsa2048', interactive=False)
            assert mock_validator.min_entropy_bytes == 768

            # Test RSA 4096
            mock_validator.min_entropy_bytes = 512  # Reset
            validate_entropy_for_key_generation('rsa4096', interactive=False)
            assert mock_validator.min_entropy_bytes == 1024


class TestEntropyValidatorMainExecution:
    """Test the __main__ execution path - covers lines 286-287."""

    def test_entropy_validator_main_execution(self):
        """Test entropy validator when run as main module - covers lines 286-287."""
        import subprocess
        import sys
        from pathlib import Path

        # Test the __main__ execution by running the entropy_validator module as main
        # Use dynamic path resolution based on current test file location
        script_path = Path(__file__).parent.parent / 'entropy_validator.py'
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            cwd=str(script_path.parent)
        )

        assert result.returncode == 0
        assert "Entropy Validation Report" in result.stdout