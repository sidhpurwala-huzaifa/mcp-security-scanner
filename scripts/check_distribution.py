"""Check release artifacts and load the bundled schema from an isolated install.

Run after `python -m build`: python scripts/check_distribution.py dist
No scanner dependencies or access to an MCP server are required.
"""

import argparse
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


def check_distribution(dist_dir: Path) -> None:
    wheels = list(dist_dir.glob("*.whl"))
    sdists = list(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")

    wheel = wheels[0].resolve()
    sdist = sdists[0].resolve()
    resource = "mcp_scanner/scanner_specs.schema"
    with zipfile.ZipFile(wheel) as archive:
        wheel_schema = archive.read(resource)
    with tarfile.open(sdist, "r:gz") as archive:
        member = archive.extractfile(f"{sdist.name[:-7]}/src/{resource}")
        if member is None:
            raise ValueError("Schema is not a regular file in the source distribution")
        with member:
            sdist_schema = member.read()
    if not wheel_schema or wheel_schema != sdist_schema:
        raise ValueError("Wheel and source distribution must contain the same nonempty schema")

    with tempfile.TemporaryDirectory(prefix="mcp-package-check-") as directory:
        root = Path(directory)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(
            [str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
            cwd=root, check=True,
        )
        # -I ignores PYTHONPATH/user site packages; cwd is outside the checkout.
        # This proves load_spec() uses the installed resource, not the source tree
        # or the editable developer installation that can hide issue #13.
        subprocess.run(
            [str(python), "-I", "-c", """
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path
import sys
import mcp_scanner
from mcp_scanner.spec import load_spec

package_path = Path(mcp_scanner.__file__).resolve()
assert package_path.is_relative_to(Path(sys.prefix).resolve()), package_path
assert files('mcp_scanner').joinpath('scanner_specs.schema').is_file()
checks = load_spec()
assert 'BASE-01' in checks and 'X-01' in checks, checks.keys()
assert all(key == check.id for key, check in checks.items())
print(f"Installed mcp-security-scanner {version('mcp-security-scanner')}: loaded {len(checks)} checks")
"""],
            cwd=root, check=True,
        )
    print(f"Validated {wheel.name} and {sdist.name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path)
    check_distribution(parser.parse_args().dist_dir)
