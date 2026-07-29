#!/usr/bin/env python3
"""
OAuth2 Device Code Flow authentication for SKA APIs.

This module implements OAuth2 device code flow to authenticate users and obtain
access tokens for the Data Management and Site Capabilities APIs.
"""

import base64
import binascii
import grp
import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional, Tuple
import requests
from xml.etree import ElementTree as ET


USER_PROFILE_ENDPOINT = os.environ.get("CONJUNCTION_IAM_USERINFO_URL", "https://ska-iam.stfc.ac.uk/userinfo")
DEFAULT_VP_SPACE_BASE_URL = "https://src.canfar.net/cavern/nodes/projects"


# Authentication endpoints
AUTHN_BASE_URL = os.environ.get("CONJUNCTION_AUTHN_BASE_URL", "https://authn.srcnet.skao.int/api/v1")
DATA_MANAGEMENT = "data-management-api"
SITE_CAPABILITIES = "site-capabilities-api"


class OAuth2AuthenticationError(Exception):
    """Exception raised for OAuth2 authentication errors."""

    pass


def decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError, binascii.Error):
        return {}


def get_client_id_from_cached_tokens() -> Optional[str]:
    tokens = load_tokens_from_cache(ignore_expiration=True)
    if not tokens:
        return None

    client_id = tokens.get("client_id")
    if isinstance(client_id, str) and client_id.strip():
        return client_id.strip()

    iam_token = tokens.get("iam_access_token")
    if isinstance(iam_token, str) and iam_token.strip():
        payload = decode_jwt_payload(iam_token)
        candidate = payload.get("client_id") or payload.get("azp") or payload.get("aud")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        if isinstance(candidate, list) and candidate:
            first = candidate[0]
            if isinstance(first, str) and first.strip():
                return first.strip()

    return None


def get_oauth_client_secret() -> Optional[str]:
    secret = os.environ.get("CONJUNCTION_CLIENT_SECRET")
    if isinstance(secret, str) and secret.strip():
        return secret.strip()
    return None


def build_oauth_client_payload(payload: dict[str, str]) -> dict[str, str]:
    client_secret = get_oauth_client_secret()
    if client_secret:
        payload["client_secret"] = client_secret
    return payload


def get_oauth_client_id() -> str:
    client_id = os.environ.get("CONJUNCTION_CLIENT_ID")
    if client_id and client_id.strip():
        return client_id.strip()

    client_id = get_client_id_from_cached_tokens()
    if client_id:
        return client_id

    raise OAuth2AuthenticationError(
        "CONJUNCTION_CLIENT_ID is required for OAuth device flow. "
        "Set this environment variable to the registered IAM OAuth client ID, "
        "or run a fresh authentication flow with an existing cached token."
    )


def validate_cached_tokens(tokens: dict[str, str]) -> bool:
    iam_token = tokens.get("iam_access_token")
    if not isinstance(iam_token, str) or not iam_token.strip():
        return False

    try:
        get_user_profile(iam_token)
        return True
    except OAuth2AuthenticationError:
        return False


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

        expired_tokens = load_tokens_from_cache(ignore_expiration=True)
        if expired_tokens:
            if validate_cached_tokens(expired_tokens):
                return expired_tokens

    # Perform full authentication flow
    device_info = initiate_device_code_flow()
    display_user_instructions(device_info)

    token_data = poll_for_authentication(device_info)
    return finalize_token_data(token_data)


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


def normalize_token_payload(token_data: dict[str, Any]) -> dict[str, Any]:
    if "token" in token_data and isinstance(token_data["token"], dict):
        nested = token_data["token"]
        # Preserve top-level token_data fields only if not shadowed.
        normalized = {**token_data, **nested}
        normalized.pop("token", None)
        return normalized
    return token_data


def finalize_token_data(token_data: dict[str, Any]) -> dict[str, str]:
    """Normalize token response and cache the resulting credentials."""
    token_data = normalize_token_payload(token_data)

    auth_token = token_data.get("access_token")
    if not auth_token and isinstance(token_data.get("token"), str):
        auth_token = token_data.get("token")
    if not isinstance(auth_token, str) or not auth_token.strip():
        raise OAuth2AuthenticationError("No IAM access token received")

    dm_token = exchange_token_for_api_token(auth_token, DATA_MANAGEMENT)
    sc_token = exchange_token_for_api_token(auth_token, SITE_CAPABILITIES)

    tokens: dict[str, str] = {
        "iam_access_token": auth_token,
        "data_management_token": dm_token,
        "site_capabilities_token": sc_token,
    }

    client_id = token_data.get("client_id") or os.environ.get("CONJUNCTION_CLIENT_ID")
    if isinstance(client_id, str) and client_id.strip():
        tokens["client_id"] = client_id.strip()

    refresh_token = token_data.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token.strip():
        tokens["refresh_token"] = refresh_token

    expires_in = token_data.get("expires_in")
    if isinstance(expires_in, int) and expires_in > 0:
        save_tokens_to_cache(tokens, expires_in=expires_in)
    else:
        save_tokens_to_cache(tokens)

    return tokens


def load_tokens_from_cache(ignore_expiration: bool = False) -> Optional[dict[str, str]]:
    """Load authentication tokens from cache.

    Returns:
        Dictionary containing tokens if found and valid. If ignore_expiration is True,
        expired cached tokens are returned as well.
    """
    cache_path = get_token_cache_path()

    if not cache_path.exists():
        return None

    try:
        cache_data = json.loads(cache_path.read_text())
        expires_at = datetime.fromisoformat(cache_data["expires_at"])

        if datetime.now() >= expires_at:
            if ignore_expiration:
                return cache_data["tokens"]
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


def initiate_device_code_flow() -> dict[str, Any]:
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
    authn_base = AUTHN_BASE_URL.rstrip('/')
    legacy_url = f"{authn_base}/login/device"

    try:
        response = requests.get(legacy_url, timeout=10)
        if response.status_code == 200:
            return response.json()
        if response.status_code not in (404, 405):
            response.raise_for_status()
    except requests.exceptions.RequestException:
        pass

    client_id = get_oauth_client_id()
    scope = os.environ.get("CONJUNCTION_OIDC_SCOPE", "openid profile offline_access")

    try:
        response = requests.post(
            f"{authn_base}/devicecode",
            data=build_oauth_client_payload({"client_id": client_id, "scope": scope}),
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
    device_info: dict[str, Any], interval: int = 5, timeout: int = 300
) -> dict[str, Any]:
    """Poll the authorization server for the device code grant.

    Args:
        device_info: The response from the device authorization endpoint.
        interval: Polling interval in seconds.
        timeout: Maximum time to poll in seconds.

    Returns:
        The token response dict.

    Raises:
        OAuth2AuthenticationError: If polling fails or times out.
    """
    device_code = device_info["device_code"]
    interval = int(device_info.get("interval", interval))
    authn_base = AUTHN_BASE_URL.rstrip('/')
    legacy_token_url = f"{authn_base}/token"
    oidc_token_url = f"{authn_base}/token"
    start_time = time.time()

    while time.time() - start_time < timeout:
        # Try the legacy authn flow first.
        try:
            response = requests.get(
                legacy_token_url,
                params={"device_code": device_code},
                timeout=10,
            )

            if response.status_code == 200:
                token_data = response.json()
                if not isinstance(token_data, dict):
                    raise OAuth2AuthenticationError(
                        "Unexpected token response format"
                    )
                return token_data

            if response.status_code not in (404, 405):
                error_data = response.json()
                error, error_description = parse_wrapped_error_response(error_data)
                if error == "authorization_pending":
                    time.sleep(interval)
                    continue
                if error == "slow_down":
                    interval += 5
                    time.sleep(interval)
                    continue
                if error == "expired_token":
                    raise OAuth2AuthenticationError(
                        "Device code expired. Please try again."
                    )
                if error == "access_denied":
                    raise OAuth2AuthenticationError("User denied authorization.")
                raise OAuth2AuthenticationError(
                    f"Authorization error: {error_description or error}"
                )
        except requests.exceptions.RequestException:
            pass

        # Fall back to OIDC-style device code polling.
        client_id = get_oauth_client_id()
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }
        try:
            response = requests.post(
                oidc_token_url,
                data=build_oauth_client_payload(data),
                timeout=10,
            )

            if response.status_code == 200:
                token_data = response.json()
                if not isinstance(token_data, dict):
                    raise OAuth2AuthenticationError(
                        "Unexpected token response format"
                    )
                return token_data

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
            elif error == "invalid_client":
                if get_oauth_client_secret() is None:
                    raise OAuth2AuthenticationError(
                        "Invalid client during device-token polling. "
                        "This client appears to require a secret. "
                        "Set CONJUNCTION_CLIENT_SECRET or use a registered public device client."
                    )
                raise OAuth2AuthenticationError(
                    f"Invalid client during device-token polling: {error_description or error}"
                )
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


def refresh_auth_token(refresh_token: str) -> dict[str, Any]:
    """Refresh an expired auth token using a refresh token."""
    client_id = get_oauth_client_id()
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    try:
        response = requests.post(
            f"{AUTHN_BASE_URL.rstrip('/')}/token",
            data=build_oauth_client_payload(data),
            timeout=10,
        )
        if response.status_code == 405:
            # Some legacy IAM endpoints only support GET for token exchange.
            response = requests.get(
                f"{AUTHN_BASE_URL.rstrip('/')}/token",
                params=build_oauth_client_payload(data),
                timeout=10,
            )

        response.raise_for_status()
        token_data = response.json()
        if not isinstance(token_data, dict):
            raise OAuth2AuthenticationError("Unexpected token response format")
        return token_data
    except requests.exceptions.RequestException as e:
        raise OAuth2AuthenticationError(f"Failed to refresh auth token: {e}")


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
