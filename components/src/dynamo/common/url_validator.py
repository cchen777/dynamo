# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
URL Validator Module

Provides URL validation and allowlist filtering to protect against SSRF
(Server-Side Request Forgery) attacks. Only URLs matching the configured
allowlist will be permitted for external HTTP requests.

Environment Variables:
    DYNAMO_ALLOWED_DOMAINS: Comma-separated list of allowed domains
                           (e.g., "example.com,cdn.example.org")
    DYNAMO_ALLOW_SUBDOMAINS: Whether to allow subdomains of allowed domains
                            (default: "true")
"""

import ipaddress
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class URLValidationError(Exception):
    """Raised when a URL fails validation against the allowlist."""

    pass


class URLValidator:
    """
    Validates URLs against an allowlist of allowed domains.

    This validator checks:
    1. URL scheme (only http, https, and data URLs are allowed)
    2. Private/internal IP addresses are blocked
    3. Hostnames that resolve to private IPs are blocked
    4. Domain must be in the allowlist (or a subdomain if enabled)
    """

    def __init__(
        self,
        allowed_domains: Optional[set[str]] = None,
        allow_subdomains: Optional[bool] = None,
    ):
        """
        Initialize the URL validator.

        Args:
            allowed_domains: Set of allowed domains. If None, reads from
                           DYNAMO_ALLOWED_DOMAINS environment variable.
            allow_subdomains: Whether to allow subdomains. If None, reads from
                            DYNAMO_ALLOW_SUBDOMAINS environment variable.
        """
        if allowed_domains is not None:
            self._allowed_domains = {d.lower() for d in allowed_domains}
        else:
            self._allowed_domains = self._parse_allowed_domains_from_env()

        if allow_subdomains is not None:
            self._allow_subdomains = allow_subdomains
        else:
            self._allow_subdomains = (
                os.environ.get("DYNAMO_ALLOW_SUBDOMAINS", "true").lower() == "true"
            )

        if self._allowed_domains:
            logger.info(
                f"URL validator initialized with allowed domains: {self._allowed_domains}, "
                f"allow_subdomains: {self._allow_subdomains}"
            )
        else:
            logger.warning(
                "URL validator initialized with no allowed domains. "
                "All external URLs will be blocked. "
                "Set DYNAMO_ALLOWED_DOMAINS to allow specific domains."
            )

    def _parse_allowed_domains_from_env(self) -> set[str]:
        """Parse allowed domains from environment variable."""
        domains_str = os.environ.get("DYNAMO_ALLOWED_DOMAINS", "")
        if not domains_str:
            return set()
        return {d.strip().lower() for d in domains_str.split(",") if d.strip()}

    def _is_private_ip(self, ip_str: str) -> bool:
        """
        Check if an IP address is private, loopback, or reserved.

        Args:
            ip_str: IP address string to check

        Returns:
            True if the IP is private/internal, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_link_local
                or ip.is_multicast
            )
        except ValueError:
            return False

    def _is_domain_allowed(self, hostname: str) -> bool:
        """
        Check if a hostname is in the allowlist.

        Args:
            hostname: The hostname to check

        Returns:
            True if the domain is allowed, False otherwise
        """
        hostname_lower = hostname.lower()

        # Direct match
        if hostname_lower in self._allowed_domains:
            return True

        # Subdomain match (if enabled)
        if self._allow_subdomains:
            for domain in self._allowed_domains:
                if hostname_lower.endswith("." + domain):
                    return True

        return False

    def validate_url(self, url: str) -> None:
        """
        Validate a URL against the allowlist.

        Args:
            url: The URL to validate

        Raises:
            URLValidationError: If the URL is not allowed
        """
        parsed = urlparse(url)

        # Only allow http, https, and data schemes
        if parsed.scheme not in ("http", "https", "data"):
            raise URLValidationError(
                f"URL scheme '{parsed.scheme}' is not allowed. "
                "Only 'http', 'https', and 'data' URLs are permitted."
            )

        # Data URLs are always allowed (no network access)
        if parsed.scheme == "data":
            return

        hostname = parsed.hostname
        if not hostname:
            raise URLValidationError("URL has no hostname")

        # Block direct IP addresses that are private/internal
        if self._is_private_ip(hostname):
            raise URLValidationError(
                f"Access to private/internal IP address '{hostname}' is not allowed"
            )

        # Resolve hostname and check if it resolves to a private IP
        # This prevents DNS rebinding attacks
        try:
            resolved_ip = socket.gethostbyname(hostname)
            if self._is_private_ip(resolved_ip):
                raise URLValidationError(
                    f"Hostname '{hostname}' resolves to private/internal IP address"
                )
        except socket.gaierror:
            # DNS resolution failed - let the actual HTTP request handle this
            pass

        # Check domain allowlist
        if not self._allowed_domains:
            raise URLValidationError(
                "No allowed domains configured. "
                "Set DYNAMO_ALLOWED_DOMAINS environment variable to allow external URLs."
            )

        if not self._is_domain_allowed(hostname):
            raise URLValidationError(
                f"Domain '{hostname}' is not in the allowed domains list"
            )

    def is_url_allowed(self, url: str) -> bool:
        """
        Check if a URL is allowed without raising an exception.

        Args:
            url: The URL to check

        Returns:
            True if the URL is allowed, False otherwise
        """
        try:
            self.validate_url(url)
            return True
        except URLValidationError:
            return False


# Global singleton instance
_validator: Optional[URLValidator] = None


def get_url_validator() -> URLValidator:
    """
    Get or create the global URL validator instance.

    Returns:
        The global URLValidator instance
    """
    global _validator
    if _validator is None:
        _validator = URLValidator()
    return _validator


def validate_url(url: str) -> None:
    """
    Validate a URL using the global validator.

    This is a convenience function that uses the global validator instance.

    Args:
        url: The URL to validate

    Raises:
        URLValidationError: If the URL is not allowed
    """
    get_url_validator().validate_url(url)


def is_url_allowed(url: str) -> bool:
    """
    Check if a URL is allowed using the global validator.

    This is a convenience function that uses the global validator instance.

    Args:
        url: The URL to check

    Returns:
        True if the URL is allowed, False otherwise
    """
    return get_url_validator().is_url_allowed(url)
