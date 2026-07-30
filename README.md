# conjunction

`conjunction` is a small Python utility for mounting SKA project directories from `/skaprojects` into a local user's home directory. It authenticates with SKA IAM using OAuth2 device code flow, resolves user identity, and performs bind mounts as root.

## Repository layout

- `conjunction-python/conjunction.py` - Main mount/unmount CLI script.
- `conjunction-python/oauth.py` - OAuth2 device code flow helper and token cache management.
- `conjunction-python/conjunction.config` - Deployment-specific defaults for VP Space and POSIX mapper endpoints.

## Requirements

- Python 3
- `requests` Python package
- `bindfs` installed on the host
- Root or sudo privileges to mount and unmount project directories

## Installation

There is no packaged installer in this repository. Use the files directly from `conjunction-python/`.

## Configuration

`conjunction-python/conjunction.config` can define deployment defaults:

- `VP_SPACE_BASE_URL` - VP Space API base URL
- `POSIX_MAPPER_BASE_URL` - POSIX mapper service URL

If `conjunction.config` is not found in `/etc/conjunction/`, `/usr/local/etc/conjunction/`, or the script directory, environment variables may be used instead.

## Environment variables

- `CONJUNCTION_CLIENT_ID` - Required OAuth client ID for device code flow.
- `CONJUNCTION_CLIENT_SECRET` - Optional OAuth client secret for confidential clients.
- `CONJUNCTION_AUTHN_BASE_URL` - OAuth2 authentication base URL (default: `https://authn.srcnet.skao.int/api/v1`).
- `CONJUNCTION_IAM_USERINFO_URL` - IAM user info endpoint (default: `https://ska-iam.stfc.ac.uk/userinfo`).
- `CONJUNCTION_VP_SPACE_BASE_URL` - Override VP Space base URL.
- `CONJUNCTION_OIDC_SCOPE` - OAuth scope for device flow (default: `openid profile offline_access`).

## Token cache behavior

The OAuth helper caches tokens under the invoking user's config directory:

- `~/.config/conjuction/tokens.json`

When the script is run with `sudo`, the cache directory and token file are corrected to the original local user owner, preventing root-owned token files.

## Usage

Run the script as root or via `sudo`.

Mount a project:

```bash
sudo python3 conjunction-python/conjunction.py --mount <project_name>
```

Unmount a project:

```bash
sudo python3 conjunction-python/conjunction.py --unmount <project_name>
```

Example:

```bash
sudo python3 conjunction-python/conjunction.py --mount example-project
```

## How it works

1. The CLI loads deployment config and ensures it is running as root.
2. On `--mount`, it authenticates using OAuth2 device code flow via `oauth.py`.
3. It fetches the IAM user profile and resolves an IAM username.
4. It queries a POSIX mapper endpoint for UID/GID. (This will be replaced with KeyCloak integration.)
5. It bind-mounts `/skaprojects/<project_name>` into `/home/<sudo_user>/projects/<project_name>` using `bindfs`.
6. On `--unmount`, it unmounts the target mountpoint.

## Notes

- The script currently skips VP Space lookups until the endpoint is configured correctly.
- The mount target is always created under `/home/<invoking_user>/projects/`.
- The CLI logs errors to `/var/log/projects.log` when possible.

## License

This repository is published under the license defined in `LICENSE`.
