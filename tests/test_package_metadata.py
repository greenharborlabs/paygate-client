from importlib.metadata import PackageNotFoundError, version as installed_package_version
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path
from typing import Iterator, Optional

from email import message_from_bytes
from email.message import Message

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from paygate_client import __version__


ROOT = Path(__file__).resolve().parents[1]
try:
    installed_package_version("build")
    BUILD_AVAILABLE = True
except PackageNotFoundError:
    BUILD_AVAILABLE = False


def _run(*args: str, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONNOUSERSITE": "1"},
    )


def _artifact_metadata(path: Path) -> Message:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as artifact:
            metadata_name = next(name for name in artifact.namelist() if name.endswith("/METADATA"))
            return message_from_bytes(artifact.read(metadata_name))
    with tarfile.open(path) as artifact:
        metadata_name = next(
            member.name for member in artifact.getmembers() if member.name.endswith("/PKG-INFO")
        )
        metadata_file = artifact.extractfile(metadata_name)
        assert metadata_file is not None
        return message_from_bytes(metadata_file.read())


def _build_clean_archive(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Build from an archive of an isolated snapshot of the current package tree."""
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    tracked_files = _run("git", "ls-files", "-z", cwd=ROOT).stdout.split("\0")
    for filename in filter(None, tracked_files):
        source_file = ROOT / filename
        if source_file.is_file():
            destination = snapshot / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)

    # The package README is deliberately new during this release-preparation
    # work. Include it explicitly while otherwise limiting the snapshot to
    # tracked package files, so the test remains runnable before a commit.
    shutil.copy2(ROOT / "PYPI_README.md", snapshot / "PYPI_README.md")
    _run("git", "init", "-q", cwd=snapshot)
    _run("git", "add", "--all", cwd=snapshot)
    _run(
        "git",
        "-c",
        "user.name=Package artifact test",
        "-c",
        "user.email=package-artifact-test@example.invalid",
        "commit",
        "-q",
        "-m",
        "package artifact snapshot",
        cwd=snapshot,
    )

    archive = tmp_path / "source.tar"
    with archive.open("wb") as stream:
        subprocess.run(
            ["git", "archive", "--format=tar", "HEAD"],
            cwd=snapshot,
            check=True,
            stdout=stream,
        )
    source = tmp_path / "source"
    source.mkdir()
    with tarfile.open(archive) as git_archive:
        git_archive.extractall(source)
    assert (source / "PYPI_README.md").is_file()
    dist = tmp_path / "dist"
    _run(sys.executable, "-m", "build", "--outdir", str(dist), cwd=source)
    sdist = next(dist.glob("*.tar.gz"))
    wheel = next(dist.glob("*.whl"))
    return source, sdist, wheel


@pytest.fixture(scope="module")
def built_artifacts() -> Iterator[tuple[Path, Path, Path]]:
    if not BUILD_AVAILABLE:
        pytest.skip("package artifact tests require `pip install -e '.[dev]'`")
    with tempfile.TemporaryDirectory(prefix="paygate-package-test-") as directory:
        yield _build_clean_archive(Path(directory))


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _assert_import_comes_from(
    python: Path, external_cwd: Path, expected_directory: Path
) -> None:
    result = _run(
        str(python),
        "-c",
        "import paygate_client; print(paygate_client.__version__); print(paygate_client.__file__)",
        cwd=external_cwd,
    )
    version, module_file = result.stdout.splitlines()
    assert version == "0.1.0"
    assert _is_within(Path(module_file), expected_directory)
    assert not _is_within(Path(module_file), ROOT)


def _assert_installed_artifact(environment: Path, artifact: Path, external_cwd: Path) -> None:
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _run(str(python), "-m", "pip", "install", str(artifact), cwd=external_cwd)
    _assert_import_comes_from(python, external_cwd, environment)
    executable = environment / ("Scripts/paygate.exe" if os.name == "nt" else "bin/paygate")
    assert _run(str(executable), "--version", cwd=external_cwd).stdout.strip() == "0.1.0"
    assert "Paygate command-line client." in _run(str(executable), "--help", cwd=external_cwd).stdout


def _require_tag_matches_artifact(tag: str, artifact: Path) -> None:
    """Model the pre-publication version gate without invoking a publisher."""
    artifact_version = _artifact_metadata(artifact)["Version"]
    if tag.removeprefix("v") != artifact_version:
        raise ValueError(
            "release tag %s does not match artifact version %s" % (tag, artifact_version)
        )


def _pyproject() -> dict[str, object]:
    return tomllib.loads(Path("pyproject.toml").read_text())


def test_project_version_is_dynamically_read_from_package() -> None:
    pyproject = _pyproject()
    project = pyproject["project"]

    assert "version" not in project
    assert project["dynamic"] == ["version"]
    assert pyproject["tool"]["setuptools"]["dynamic"] == {
        "version": {"attr": "paygate_client.__version__"}
    }
    assert __version__ == "0.1.0"


def test_project_declares_release_metadata_and_breez_compatibility() -> None:
    pyproject = _pyproject()
    project = pyproject["project"]

    assert pyproject["build-system"]["requires"] == ["setuptools>=77.0.3", "wheel"]
    assert project["readme"] == {"file": "PYPI_README.md", "content-type": "text/markdown"}
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert project["requires-python"] == ">=3.9,<3.15"
    assert project["authors"] == [{"name": "Green Harbor Labs", "email": "mark@greenharborlabs.com"}]
    assert project["maintainers"] == [{"name": "Green Harbor Labs", "email": "mark@greenharborlabs.com"}]
    assert project["urls"] == {
        "Homepage": "https://github.com/greenharborlabs/paygate-client",
        "Source": "https://github.com/greenharborlabs/paygate-client",
        "Issues": "https://github.com/greenharborlabs/paygate-client/issues",
        "Documentation": "https://github.com/greenharborlabs/paygate-client/tree/main/docs",
    }
    assert "breez" in project["optional-dependencies"]
    assert all(";" not in requirement for requirement in project["optional-dependencies"]["breez"])
    assert "Programming Language :: Python :: 3.14" in project["classifiers"]


def test_pypi_readme_contains_only_post_publication_install_guidance() -> None:
    readme = Path("PYPI_README.md").read_text()

    assert 'pipx install "paygate-client[breez]"' in readme
    assert "https://github.com/greenharborlabs/paygate-client" in readme
    assert "https://github.com/greenharborlabs/paygate-client/tree/main/docs" in readme
    assert "unverified" in readme
    assert "declared" in readme
    assert "W2 CI" in readme
    assert "tested" not in readme.lower()
    assert "Breez support is supported" not in readme


def test_clean_git_archive_builds_artifacts_with_exact_metadata(
    built_artifacts: tuple[Path, Path, Path],
) -> None:
    source, sdist, wheel = built_artifacts
    expected_description = (source / "PYPI_README.md").read_text()

    with tarfile.open(sdist) as artifact:
        names = artifact.getnames()
        assert any(name.endswith("/PYPI_README.md") for name in names)
        assert any(name.endswith("/LICENSE") for name in names)
    with zipfile.ZipFile(wheel) as artifact:
        assert any(name.endswith("/licenses/LICENSE") for name in artifact.namelist())

    for artifact in (sdist, wheel):
        metadata = _artifact_metadata(artifact)
        assert metadata["Version"] == __version__ == "0.1.0"
        assert metadata["License-Expression"] == "MIT"
        assert SpecifierSet(metadata["Requires-Python"]) == SpecifierSet(">=3.9,<3.15")
        assert metadata["Description-Content-Type"] == "text/markdown"
        assert metadata.get_payload() == expected_description
        assert "Green Harbor Labs" in metadata["Author-email"]
        assert "Green Harbor Labs" in metadata["Maintainer-email"]
        assert metadata.get_all("Project-URL") == [
            "Homepage, https://github.com/greenharborlabs/paygate-client",
            "Source, https://github.com/greenharborlabs/paygate-client",
            "Issues, https://github.com/greenharborlabs/paygate-client/issues",
            "Documentation, https://github.com/greenharborlabs/paygate-client/tree/main/docs",
        ]
        assert "breez" in metadata.get_all("Provides-Extra")
        assert "Programming Language :: Python :: 3.14" in metadata.get_all("Classifier")

    with zipfile.ZipFile(wheel) as artifact:
        entry_points = next(name for name in artifact.namelist() if name.endswith("/entry_points.txt"))
        assert "paygate = paygate_client.cli:app" in artifact.read(entry_points).decode()


def test_artifacts_install_in_separate_environments(
    built_artifacts: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    _, sdist, wheel = built_artifacts
    for name, artifact in (("wheel", wheel), ("sdist", sdist)):
        environment = tmp_path / name
        external_cwd = tmp_path / (name + "-cwd")
        external_cwd.mkdir()
        venv.EnvBuilder(with_pip=True, upgrade_deps=True).create(environment)
        _assert_installed_artifact(environment, artifact, external_cwd)


def test_source_and_editable_installs_report_the_authoritative_version(tmp_path: Path) -> None:
    if not BUILD_AVAILABLE:
        pytest.skip("package artifact tests require `pip install -e '.[dev]'`")
    source, _, _ = _build_clean_archive(tmp_path)
    for name, requirement in (("source", str(source)), ("editable", "-e")):
        environment = tmp_path / name
        external_cwd = tmp_path / (name + "-cwd")
        external_cwd.mkdir()
        venv.EnvBuilder(with_pip=True, upgrade_deps=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        command = [str(python), "-m", "pip", "install"]
        command.extend([requirement, str(source)] if requirement == "-e" else [requirement])
        _run(*command, cwd=external_cwd)
        _assert_import_comes_from(
            python, external_cwd, source if requirement == "-e" else environment
        )
        executable = environment / ("Scripts/paygate.exe" if os.name == "nt" else "bin/paygate")
        assert _run(str(executable), "--version", cwd=external_cwd).stdout.strip() == "0.1.0"
        assert "Paygate command-line client." in _run(str(executable), "--help", cwd=external_cwd).stdout


def test_release_tag_must_match_built_artifact_version(
    built_artifacts: tuple[Path, Path, Path]
) -> None:
    _, _, wheel = built_artifacts
    with pytest.raises(ValueError, match="does not match artifact version"):
        _require_tag_matches_artifact("v0.1.1", wheel)


def test_requires_python_rejects_python_315(
    built_artifacts: tuple[Path, Path, Path]
) -> None:
    _, _, wheel = built_artifacts
    requires_python = _artifact_metadata(wheel)["Requires-Python"]
    assert Version("3.15") not in SpecifierSet(requires_python)
