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

import logging
from typing import Optional

import httpx

from dynamo.common.url_validator import URLValidationError, validate_url

logger = logging.getLogger(__name__)

# Global HTTP client instance
_global_http_client: Optional[httpx.AsyncClient] = None


def get_http_client(timeout: float = 60.0) -> httpx.AsyncClient:
    """
    Get or create a shared HTTP client instance.

    Args:
        timeout: Timeout for HTTP requests

    Returns:
        Shared HTTP client instance
    """
    global _global_http_client

    if _global_http_client is None or _global_http_client.is_closed:
        _global_http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )
        logger.info(f"Shared HTTP client initialized with timeout={timeout}s")

    return _global_http_client


async def fetch_url(
    url: str, timeout: float = 60.0, validate: bool = True
) -> httpx.Response:
    """
    Fetch a URL with optional URL validation.

    This function validates the URL against the allowlist before making the
    request to protect against SSRF attacks.

    Args:
        url: The URL to fetch
        timeout: Timeout for the HTTP request
        validate: Whether to validate the URL against the allowlist (default: True)

    Returns:
        The HTTP response

    Raises:
        URLValidationError: If the URL is not in the allowlist
        httpx.HTTPError: If the HTTP request fails
    """
    if validate:
        validate_url(url)

    client = get_http_client(timeout)
    response = await client.get(url)
    response.raise_for_status()
    return response


__all__ = [
    "get_http_client",
    "fetch_url",
    "validate_url",
    "URLValidationError",
]
