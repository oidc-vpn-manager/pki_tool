#!/usr/bin/env python3
"""
Entropy validation utilities for PKI key generation.

This module provides entropy validation to ensure sufficient randomness
for cryptographic key generation operations.
"""

import os
import sys
import time
import click
from typing import Dict, List, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EntropyValidator:
    """Validates system entropy for cryptographic operations."""

    def __init__(self):
        self.min_entropy_bytes = 512  # Minimum entropy pool size
        self.min_entropy_quality = 0.7  # Minimum entropy quality (0-1)
        self.entropy_sources = [
            '/dev/random',
            '/dev/urandom',
            '/proc/sys/kernel/random/entropy_avail'
        ]

    def check_system_entropy(self) -> Tuple[bool, Dict]:
        """
        Check system entropy availability and quality.

        Returns:
            Tuple of (is_sufficient, entropy_info)
        """
        entropy_info = {
            'available_entropy': 0,
            'entropy_quality': 0.0,
            'sources_available': [],
            'warnings': [],
            'recommendations': []
        }

        # Check available entropy on Linux systems
        entropy_file = '/proc/sys/kernel/random/entropy_avail'
        if os.path.exists(entropy_file):
            try:
                with open(entropy_file, 'r') as f:
                    entropy_info['available_entropy'] = int(f.read().strip())
            except (IOError, ValueError) as e:
                entropy_info['warnings'].append(f"Could not read entropy_avail: {e}")

        # Check entropy sources availability
        for source in self.entropy_sources:
            if os.path.exists(source):
                entropy_info['sources_available'].append(source)

        # Validate entropy quality through randomness testing
        entropy_info['entropy_quality'] = self._test_entropy_quality()

        # Determine if entropy is sufficient
        is_sufficient = (
            entropy_info['available_entropy'] >= self.min_entropy_bytes and
            entropy_info['entropy_quality'] >= self.min_entropy_quality and
            len(entropy_info['sources_available']) >= 2
        )

        # Add recommendations if insufficient
        if not is_sufficient:
            self._add_entropy_recommendations(entropy_info)

        return is_sufficient, entropy_info

    def _test_entropy_quality(self, sample_size: int = 1024) -> float:
        """
        Test entropy quality by analyzing randomness of os.urandom().

        Returns:
            Quality score between 0.0 and 1.0
        """
        try:
            # Generate random sample
            random_data = os.urandom(sample_size)

            # Test 1: Byte distribution (should be fairly uniform)
            byte_counts = [0] * 256
            for byte in random_data:
                byte_counts[byte] += 1

            # Calculate uniformity (lower chi-square is better)
            expected = sample_size / 256
            chi_square = sum((count - expected) ** 2 / expected for count in byte_counts)
            uniformity_score = max(0, 1 - (chi_square / (255 * expected)))

            # Test 2: Consecutive patterns (fewer patterns is better)
            patterns = {}
            for i in range(len(random_data) - 1):
                pattern = (random_data[i], random_data[i + 1])
                patterns[pattern] = patterns.get(pattern, 0) + 1

            max_pattern_count = max(patterns.values()) if patterns else 0
            pattern_score = max(0, 1 - (max_pattern_count / (sample_size * 0.1)))

            # Test 3: Bit distribution within bytes
            bit_counts = [0] * 8
            for byte in random_data:
                for i in range(8):
                    if byte & (1 << i):
                        bit_counts[i] += 1

            expected_bits = sample_size / 2
            bit_uniformity = max(0, 1 - max(abs(count - expected_bits) / expected_bits for count in bit_counts))

            # Combine scores (weighted average)
            quality_score = (
                uniformity_score * 0.4 +
                pattern_score * 0.3 +
                bit_uniformity * 0.3
            )

            return min(1.0, max(0.0, quality_score))

        except Exception as e:
            click.echo(f"Warning: Could not test entropy quality: {e}", err=True)
            return 0.5  # Assume moderate quality on test failure

    def _add_entropy_recommendations(self, entropy_info: Dict):
        """Add entropy improvement recommendations."""
        recommendations = entropy_info['recommendations']

        if entropy_info['available_entropy'] < self.min_entropy_bytes:
            recommendations.append(
                f"Increase system entropy. Current: {entropy_info['available_entropy']}, "
                f"Recommended: {self.min_entropy_bytes}+"
            )
            recommendations.append(
                "Consider installing haveged or rng-tools to improve entropy generation"
            )

        if entropy_info['entropy_quality'] < self.min_entropy_quality:
            recommendations.append(
                f"Entropy quality below threshold. Current: {entropy_info['entropy_quality']:.2f}, "
                f"Required: {self.min_entropy_quality}"
            )
            recommendations.append(
                "Ensure system has sufficient activity or hardware RNG support"
            )

        if len(entropy_info['sources_available']) < 2:
            recommendations.append(
                "Limited entropy sources available. Ensure /dev/random and /dev/urandom are accessible"
            )

        # General recommendations
        recommendations.extend([
            "For production PKI generation, use dedicated hardware with true RNG",
            "Consider generating keys on a system with keyboard/mouse activity",
            "Avoid virtualized environments for critical key generation when possible"
        ])

    def wait_for_entropy(self, timeout: int = 60) -> bool:
        """
        Wait for sufficient entropy to become available.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if entropy becomes sufficient, False if timeout
        """
        start_time = time.time()

        click.echo("Waiting for sufficient entropy...")

        while time.time() - start_time < timeout:
            is_sufficient, _ = self.check_system_entropy()
            if is_sufficient:
                return True

            # Show progress
            elapsed = int(time.time() - start_time)
            click.echo(f"  Waiting for entropy... {elapsed}s/{timeout}s", nl=False)
            click.echo("\r", nl=False)

            time.sleep(1)

        click.echo()
        return False

    def generate_entropy_report(self) -> str:
        """Generate a detailed entropy report for display."""
        is_sufficient, info = self.check_system_entropy()

        report = []
        report.append("=== Entropy Validation Report ===")
        report.append(f"Status: {'✓ SUFFICIENT' if is_sufficient else '✗ INSUFFICIENT'}")
        report.append(f"Available Entropy: {info['available_entropy']} bytes")
        report.append(f"Entropy Quality: {info['entropy_quality']:.2f} (0.0-1.0)")
        report.append(f"Sources Available: {', '.join(info['sources_available'])}")

        if info['warnings']:
            report.append("\nWarnings:")
            for warning in info['warnings']:
                report.append(f"  - {warning}")

        if info['recommendations']:
            report.append("\nRecommendations:")
            for rec in info['recommendations']:
                report.append(f"  - {rec}")

        return '\n'.join(report)


def validate_entropy_for_key_generation(key_type: str, interactive: bool = True) -> bool:
    """
    Validate entropy before key generation.

    Args:
        key_type: Type of key being generated (ed25519, rsa2048, rsa4096)
        interactive: Whether to prompt user for decisions

    Returns:
        True if validation passes or user chooses to continue
    """
    validator = EntropyValidator()

    # Adjust requirements based on key type
    if key_type in ['rsa4096']:
        validator.min_entropy_bytes = 1024  # Higher requirement for large RSA keys
    elif key_type in ['rsa2048']:
        validator.min_entropy_bytes = 768
    else:  # ed25519
        validator.min_entropy_bytes = 512

    is_sufficient, entropy_info = validator.check_system_entropy()

    if is_sufficient:
        click.secho("✓ Entropy validation passed", fg="green")
        return True

    # Show entropy report
    click.echo(validator.generate_entropy_report())

    if not interactive:
        click.secho("✗ Insufficient entropy for key generation", fg="red", err=True)
        return False

    # Interactive mode - give user options
    click.echo()
    click.secho("Insufficient entropy detected!", fg="yellow")

    options = [
        "Wait for entropy to improve (recommended)",
        "Continue anyway (not recommended for production)",
        "Abort key generation"
    ]

    choice = click.prompt(
        "Choose an option:\n" +
        "\n".join(f"  {i+1}. {opt}" for i, opt in enumerate(options)) +
        "\nEnter choice (1-3)",
        type=click.IntRange(1, 3)
    )

    if choice == 1:
        # Wait for entropy
        if validator.wait_for_entropy():
            click.secho("✓ Entropy improved - proceeding with key generation", fg="green")
            return True
        else:
            click.secho("✗ Timeout waiting for entropy", fg="red", err=True)
            return False
    elif choice == 2:
        # Continue with warning
        click.secho("⚠ Proceeding with insufficient entropy - use only for testing!", fg="yellow")
        return True
    else:
        # Abort
        click.secho("Key generation aborted", fg="red")
        return False


if __name__ == '__main__':
    # Simple CLI for testing entropy validation
    validator = EntropyValidator()
    print(validator.generate_entropy_report())