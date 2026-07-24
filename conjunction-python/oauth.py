#!/usr/bin/env python3
"""
OAuth2 Device Code Flow authentication for SKA APIs.

This module implements OAuth2 device code flow to authenticate users and obtain
access tokens for the Data Management and Site Capabilities APIs.
"""

import grp
import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple
import requests
from xml.etree import ElementTree as ET


USER_PROFILE_ENDPOINT = os.environ.get("CONJUNCTION_IAM_USERINFO_URL", "https://ska-iam.stfc.ac.uk/userinfo")
DEFAULT_VP_SPACE_BASE_URL = "https://src.canfar.net/cavern/nodes/projects"


# Authentication endpoints
AUTHN_BASE_URL = os.environ.get("CONJUNCTION_AUTHN_BASE_URL", "https://ska-iam.stfc.ac.uk")
DATA_MANAGEMENT = "data-management-api"
SITE_CAPABILITIES = "site-capabilities-api"


class OAuth2AuthenticationError(Exception):
    """Exception raised for OAuth2 authentication errors."""

    pass


def authenticate(use_cache: bool = True) -> dict[str, str]:
    """Complete OAuth2 device code flow and obtain all required API tokens.

    Args:
        use_cache: Whether to use cached tokens if available (default: True).

    Returns:
        Dict containing:
        - data_management_token: Token for Data Management API
        - site_capabilities_token: Token for Site Capabilities API

    Raises:
        OAuth2AuthenticationError: If authentication fails at any step.
    """

    # Try to load from cache first
    if use_cache:
        cached_tokens = load_tokens_from_cache()
        if cached_tokens:
            return cached_tokens

    # Perform full authentication flow
    device_info = initiate_device_code_flow()
    display_user_instructions(device_info)

    device_code = device_info["device_code"]
    interval = int(device_info.get("interval", 5))
    auth_token = poll_for_authentication(device_code, interval)

    # Get API-specific tokens
    dm_token = exchange_token_for_api_token(auth_token, DATA_MANAGEMENT)
    sc_token = exchange_token_for_api_token(auth_token, SITE_CAPABILITIES)

    tokens = {
        "iam_access_token": auth_token,
        "data_management_token": dm_token,
        "site_capabilities_token": sc_token,
    }

    # Save to cache (default expiration: 1 hour)
    save_tokens_to_cache(tokens, expires_in=3600)

    return tokens


def get_user_profile(access_token: str) -> dict[str, str]:
    """Fetch the authenticated user's profile from SKA-IAM."""
    try:
        response = requests.get(
            USER_PROFILE_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise OAuth2AuthenticationError("Unexpected user profile response format")
        return payload
    except requests.exceptions.RequestException as exc:
        raise OAuth2AuthenticationError(f"Failed to fetch user profile: {exc}")


def get_user_profile_alt(access_token: str) -> dict[str, str]:
    """Fallback profile lookup for environments that expose the IAM account API at a different base URL."""
    try:
        response = requests.get(
            f"{AUTHN_BASE_URL.rstrip('/')}/account/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise OAuth2AuthenticationError("Unexpected user profile response format")
        return payload
    except requests.exceptions.RequestException as exc:
        raise OAuth2AuthenticationError(f"Failed to fetch user profile from fallback endpoint: {exc}")


def extract_username_from_profile(profile: dict[str, str]) -> str:
    """Extract a username or user stub from an IAM profile response."""
    for key in ("preferred_username", "username", "userName", "name", "displayName"):
        value = profile.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    if isinstance(profile.get("name"), dict):
        for key in ("formatted", "givenName", "familyName"):
            value = profile["name"].get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    sub = profile.get("sub")
    if isinstance(sub, str) and sub.strip():
        return sub.strip()

    raise OAuth2AuthenticationError("Unable to determine username from IAM profile")


def extract_group_name_from_groupwrite(groupwrite: str) -> str:
    """Extract the Unix group name from a VP Space groupwrite URI."""
    if not groupwrite:
        raise OAuth2AuthenticationError("No groupwrite value returned")

    match = re.search(r"\?(.+)$", groupwrite)
    if not match:
        raise OAuth2AuthenticationError(f"Unable to parse groupwrite value: {groupwrite}")

    return match.group(1).split("/")[-1]


def get_group_gid(group_name: str) -> int:
    """Resolve a Unix group name to its GID."""
    try:
        return grp.getgrnam(group_name).gr_gid
    except KeyError as exc:
        raise OAuth2AuthenticationError(f"Group '{group_name}' was not found") from exc


def get_vospace_properties(access_token: str, project_name: str, base_url: Optional[str] = None) -> dict[str, str]:
    """Query the VP Space API for a project's creator and groupwrite values."""
    vp_space_base_url = base_url or os.environ.get("CONJUNCTION_VP_SPACE_BASE_URL") or DEFAULT_VP_SPACE_BASE_URL
    try:
        response = requests.get(
            f"{vp_space_base_url.rstrip('/')}/{project_name}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise OAuth2AuthenticationError(f"Failed to query VP Space node: {exc}")

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise OAuth2AuthenticationError(f"Failed to parse VP Space response: {exc}")

    properties: dict[str, str] = {}
    for prop in root.findall("{*}property"):
        uri = prop.attrib.get("uri", "")
        if uri and prop.text and prop.text.strip():
            properties[uri] = prop.text.strip()

    return properties


def save_tokens_to_cache(tokens: dict[str, str], expires_in: int = 3600) -> None:
    """Save authentication tokens to cache file.

    Args:
        tokens: Dictionary containing authentication tokens.
        expires_in: Token expiration time in seconds (default: 1 hour).
    """
    cache_path = get_token_cache_path()

    # Calculate expiration time
    expiration = (datetime.now() + timedelta(seconds=expires_in)).isoformat()

    cache_data = {"tokens": tokens, "expires_at": expiration}

    # Write to cache with secure permissions
    cache_path.write_text(json.dumps(cache_data, indent=2))
    os.chmod(cache_path, 0o600)  # Read/write for owner only
    print(f"Tokens cached until {expiration}")


def load_tokens_from_cache() -> Optional[dict[str, str]]:
    """Load authentication tokens from cache if valid.

    Returns:
        Dictionary containing tokens if valid, None if expired or not found.
    """
    cache_path = get_token_cache_path()

    if not cache_path.exists():
        return None

    try:
        cache_data = json.loads(cache_path.read_text())

        # Check if tokens are expired
        expires_at = datetime.fromisoformat(cache_data["expires_at"])
        if datetime.now() >= expires_at:
            print("Cached tokens expired")
            return None

        print("Using cached tokens")
        return cache_data["tokens"]

    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Invalid cache file: {e}")
        return None


def get_token_cache_path() -> Path:
    """Get the path to the token cache file.

    Returns:
        Path to the token cache file in the invoking user's config directory.
    """
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            user_home = Path("/home") / sudo_user
            config_dir = user_home / ".config" / "conjuction"
            config_dir.mkdir(parents=True, exist_ok=True)
            return config_dir / "tokens.json"

    config_dir = Path.home() / ".config" / "conjuction"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "tokens.json"


def initiate_device_code_flow() -> dict[str, str]:
    """Initiate the OAuth2 device code flow.

    Returns:
        Dict containing:
        - device_code: Code to use for polling
        - user_code: Code for user to enter
        - verification_uri: URL for user to visit
        - expires_in: Seconds until codes expire
        - interval: Polling interval in seconds

    Raises:
        OAuth2AuthenticationError: If the request fails.
    """
    try:
        # Request device and user codes from authn service
        response = requests.post(
            f"{AUTHN_BASE_URL}/devicecode",
            data={"client_id": os.environ.get("CONJUNCTION_CLIENT_ID", "")},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise OAuth2AuthenticationError(f"Failed to initiate device code flow: {e}")


def display_user_instructions(device_info: dict[str, str]) -> None:
    """Display instructions for the user to authenticate.

    Args:
        verification_uri: The URL the user should visit.
        user_code: The code the user should enter.
    """
    verification_uri = device_info["verification_uri"]
    user_code = device_info["user_code"]
    print(
        f"\nACTION REQUIRED:\n    Open this URL in a browser and authenticate: {verification_uri}?user_code={user_code}"
    )
    print("\nWaiting for authentication (timeout: 5 minutes)...")


def poll_for_authentication(
    device_code: str, interval: int = 5, timeout: int = 300
) -> str:
    """Poll the authorization server for the authorization code.

    Args:
        device_code: The device code from the initial request.
        interval: Polling interval in seconds.
        timeout: Maximum time to poll in seconds.

    Returns:
        The authorization code.

    Raises:
        OAuth2AuthenticationError: If polling fails or times out.
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(
                f"{AUTHN_BASE_URL}/token",
                params={"device_code": device_code},
                timeout=10,
            )

            if response.status_code == 200:
                token_data = response.json()
                # authn device flow returns access_token directly
                access_token_data = token_data.get("token")
                if not access_token_data:
                    raise OAuth2AuthenticationError(
                        f"No access_token in response. Received: {token_data.keys()}"
                    )
                return access_token_data.get("access_token")

            # Parse error response - API wraps IAM errors in 'detail' field
            error_data = response.json()
            error, error_description = parse_wrapped_error_response(error_data)

            if error == "authorization_pending":
                time.sleep(interval)
                continue
            elif error == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            elif error == "expired_token":
                raise OAuth2AuthenticationError(
                    "Device code expired. Please try again."
                )
            elif error == "access_denied":
                raise OAuth2AuthenticationError("User denied authorization.")
            else:
                error_msg = f"Authorization error: {error}"
                if error_description:
                    error_msg += f" - {error_description}"
                raise OAuth2AuthenticationError(error_msg)

        except requests.exceptions.RequestException as e:
            raise OAuth2AuthenticationError(f"Failed to poll for authorization: {e}")

    raise OAuth2AuthenticationError("Authorization timeout. Please try again.")


def parse_wrapped_error_response(error_data: dict) -> Tuple[Optional[str], Optional[str]]:
    """Parse error response that may be wrapped by the API.

    Args:
        error_data: The JSON error response from the API.

    Returns:
        Tuple of (error, error_description).
    """
    error = None
    error_description = None

    if "detail" in error_data:
        # Extract JSON from "response: {...}" pattern in detail string
        detail = error_data["detail"]
        match = re.search(r"response:\s*(\{.*\})\s*$", detail)
        if match:
            try:
                # Parse the embedded JSON
                embedded_json = json.loads(match.group(1))
                error = embedded_json.get("error")
                error_description = embedded_json.get("error_description")
            except json.JSONDecodeError:
                pass

    # Fallback to direct error field if not wrapped
    if not error:
        error = error_data.get("error")
        error_description = error_data.get("error_description")

    return error, error_description


def exchange_code_for_auth_token(code: str) -> str:
    """Exchange authorization code for authentication token.

    Args:
        code: The authorization code from the device flow.

    Returns:
        The authentication token.

    Raises:
        OAuth2AuthenticationError: If the exchange fails.
    """
    try:
        response = requests.get(
            f"{AUTHN_BASE_URL}/token", params={"code": code}, timeout=10
        )
        response.raise_for_status()

        token_data = response.json()
        auth_token = token_data.get("access_token") or token_data.get("token")

        if not auth_token:
            raise OAuth2AuthenticationError("No access token in response")

        return auth_token

    except requests.exceptions.RequestException as e:
        raise OAuth2AuthenticationError(f"Failed to exchange code for auth token: {e}")


def exchange_token_for_api_token(auth_token: str, api_name: str) -> str:
    """Exchange authentication token for a specific API token.

    Args:
        auth_token: The authentication token from the previous step.
        api_name: The API name ('data-management' or 'site-capabilities').

    Returns:
        The API-specific access token.

    Raises:
        OAuth2AuthenticationError: If the exchange fails.
    """
    try:
        response = requests.get(
            f"{AUTHN_BASE_URL}/token/exchange/{api_name}",
            headers={"Content-Type": "application/json"},
            params={
                "version": "latest",
                "try_use_cache": "false",
                "access_token": auth_token,
            },
            timeout=10,
        )
        response.raise_for_status()

        token_data = response.json()
        api_token = token_data.get("access_token") or token_data.get("token")

        if not api_token:
            raise OAuth2AuthenticationError(
                f"No access token in response for {api_name}"
            )

        return api_token

    except requests.exceptions.RequestException as e:
        raise OAuth2AuthenticationError(
            f"Failed to exchange token for {api_name} API: {e}"
        )


if __name__ == "__main__":
    """Test the authentication flow."""
    try:
        tokens = authenticate()
        print("Tokens obtained successfully:")
        print(f"  DM Token: {tokens['data_management_token'][:20]}...")
        print(f"  SC Token: {tokens['site_capabilities_token'][:20]}...")
    except OAuth2AuthenticationError as e:
        print(f"Authentication failed: {e}")
        exit(1)
