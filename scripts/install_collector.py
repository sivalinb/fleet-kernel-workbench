"""Install one pinned official Collector binary; verify the GitHub release digest."""

import hashlib
import json
import platform
import shutil
import tarfile
import urllib.request
from pathlib import Path

VERSION = "0.160.0"
REPOSITORY = "open-telemetry/opentelemetry-collector-releases"


def main():
    system = platform.system().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if system not in {"darwin", "linux"} or not arch:
        raise SystemExit("Native Collector installation supports macOS/Linux arm64/amd64")
    asset_name = f"otelcol-contrib_{VERSION}_{system}_{arch}.tar.gz"
    with urllib.request.urlopen(
        f"https://api.github.com/repos/{REPOSITORY}/releases/tags/v{VERSION}", timeout=30
    ) as response:
        release = json.load(response)
    asset = next(a for a in release["assets"] if a["name"] == asset_name)
    expected = asset.get("digest", "").removeprefix("sha256:")
    if len(expected) != 64:
        raise RuntimeError("Official SHA-256 digest unavailable; download refused")
    directory = Path(".runtime/bin")
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory.parent / asset_name
    urllib.request.urlretrieve(asset["browser_download_url"], archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Collector checksum mismatch")
    output = directory / "collector"
    with tarfile.open(archive) as contents:
        member = next(
            m
            for m in contents.getmembers()
            if m.isfile() and Path(m.name).name == "otelcol-contrib"
        )
        with contents.extractfile(member) as source, output.open("wb") as target:
            shutil.copyfileobj(source, target)
    output.chmod(0o755)
    print(f"Verified OpenTelemetry Collector {VERSION}")


if __name__ == "__main__":
    main()
