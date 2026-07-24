#!/usr/bin/env python3

import argparse
import getpass
import os
import shutil
import subprocess
import sys
from pathlib import Path


CONFIG_PATHS = [Path("/etc/conjunction/conjunction.config"), Path("/usr/local/etc/conjunction/conjunction.config"), Path(__file__).resolve().with_name("conjunction.config")]

from oauth import (
    OAuth2AuthenticationError,
    authenticate,
    extract_group_name_from_groupwrite,
    extract_username_from_profile,
    get_group_gid,
    get_user_profile,
    get_vospace_properties,
)


def log_error(message: str) -> None:
    log_path = Path("/var/log/projects.log")
    try:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message + "\n")
    except OSError:
        pass
    print(message, file=sys.stderr)


def is_mountpoint(path: Path) -> bool:
    if not shutil.which("mountpoint"):
        raise RuntimeError("mountpoint command not found")
    result = subprocess.run(
        ["mountpoint", "-q", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def run_command(command: list[str], *, check: bool = True) -> None:
    subprocess.run(command, check=check)


def load_config() -> dict[str, str]:
    config: dict[str, str] = {}
    for path in CONFIG_PATHS:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
        break

    return config


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mount or unmount a project from /skaprojects into the current user's home directory"
    )
    parser.add_argument("option", choices=["--mount", "--unmount"], help="Action to perform")
    parser.add_argument("project_name", help="Name of the project to mount or unmount")
    args = parser.parse_args()

    if os.geteuid() != 0:
        log_error("Please run this script with sudo or as root.")
        return 1

    config = load_config()
    if "VP_SPACE_BASE_URL" in config:
        os.environ["CONJUNCTION_VP_SPACE_BASE_URL"] = config["VP_SPACE_BASE_URL"]

    try:
        tokens = authenticate()
    except OAuth2AuthenticationError as exc:
        log_error(f"OAuth authentication failed: {exc}")
        return 1

    os.environ["CONJUNCTION_DATA_MANAGEMENT_TOKEN"] = tokens["data_management_token"]
    os.environ["CONJUNCTION_SITE_CAPABILITIES_TOKEN"] = tokens["site_capabilities_token"]
    print("OAuth tokens acquired successfully")

    try:
        profile = get_user_profile(tokens["iam_access_token"])
        iam_username = extract_username_from_profile(profile)
    except OAuth2AuthenticationError as exc:
        log_error(f"IAM profile lookup failed: {exc}")
        return 1

    os.environ["CONJUNCTION_IAM_USERNAME"] = iam_username
    print(f"Resolved IAM username: {iam_username}")

    try:
        vp_properties = get_vospace_properties(
            tokens["iam_access_token"],
            args.project_name,
            os.environ.get("CONJUNCTION_VP_SPACE_BASE_URL"),
        )
        creator = vp_properties.get("ivo://ivoa.net/vospace/core#creator", "")
        groupwrite = vp_properties.get("ivo://ivoa.net/vospace/core#groupwrite", "")
        group_name = extract_group_name_from_groupwrite(groupwrite)
        group_gid = get_group_gid(group_name)
    except OAuth2AuthenticationError as exc:
        log_error(f"VP Space lookup failed: {exc}")
        return 1

    os.environ["CONJUNCTION_VOSPACE_CREATOR"] = creator
    os.environ["CONJUNCTION_VOSPACE_GROUPWRITE"] = groupwrite
    os.environ["CONJUNCTION_VOSPACE_GROUP_NAME"] = group_name
    os.environ["CONJUNCTION_VOSPACE_GROUP_GID"] = str(group_gid)
    print(f"Resolved VP Space creator: {creator or '(none)'}")
    print(f"Resolved VP Space groupwrite: {groupwrite or '(none)'}")
    print(f"Resolved group name: {group_name}")
    print(f"Resolved group GID: {group_gid}")

    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or getpass.getuser()
    target_dir = Path("/home") / sudo_user / "projects" / args.project_name
    source_dir = Path("/skaprojects") / args.project_name

    if args.option == "--mount":
        if is_mountpoint(target_dir):
            message = (
                f"Error: {target_dir} is already mounted; aborting to avoid cyclic mounts."
            )
            log_error(message)
            return 1

        if not source_dir.exists():
            log_error(f"Error: source directory {source_dir} does not exist")
            return 1

        target_dir.mkdir(parents=True, exist_ok=True)
        run_command(["chown", "-R", f"{sudo_user}:{sudo_user}", str(target_dir)])
        run_command(["chmod", "600", str(target_dir)])

        create_for_user = iam_username
        run_command(
            [
                "bindfs",
                f"--perms=0700",
                f"--force-user={sudo_user}",
                f"--force-group={sudo_user}",
                f"--create-for-user={create_for_user}",
                f"--create-for-group={group_gid}",
                str(source_dir),
                str(target_dir),
            ]
        )
    else:
        run_command(["umount", str(target_dir)], check=False)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except subprocess.CalledProcessError as exc:
        log_error(f"Command failed with exit code {exc.returncode}: {exc.cmd}")
        raise SystemExit(exc.returncode)
    except RuntimeError as exc:
        log_error(str(exc))
        raise SystemExit(1)
