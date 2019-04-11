import pathlib
import shutil
import stat
import sys
from tarfile import TarFile
from typing import Dict, List, Tuple, Union
from zipfile import ZipFile

import requests
import structlog
from cachetools.func import ttl_cache

log = structlog.get_logger(__name__)


RAIDEN_RELEASES_URL = 'https://raiden-nightlies.ams3.digitaloceanspaces.com/'
if sys.platform == 'darwin':
    RAIDEN_RELEASES_LATEST_FILE = '_LATEST-macOS-x86_64.txt'
    RELEASE_ARCHIVE_NAME_TEMPLATE = 'raiden-v{version}-macOS-x86_64.zip'
else:
    RAIDEN_RELEASES_LATEST_FILE = '_LATEST-linux-x86_64.txt'
    RELEASE_ARCHIVE_NAME_TEMPLATE = 'raiden-v{version}-linux-x86_64.tar.gz'


@ttl_cache(maxsize=1, ttl=600)
def get_latest_release():
    """Retrieve the latest release's URL path"""
    url = RAIDEN_RELEASES_URL + RAIDEN_RELEASES_LATEST_FILE
    log.debug('Fetching latest Raiden release')
    return requests.get(url).text.strip()


def is_executable(path) -> bool:
    """Check for a set x bit on the given pathlib.Path object."""
    return path.stat().st_mode & stat.S_IXUSR == stat.S_IXUSR


class ReleaseArchive:
    """Wrapper class for extracting a Raiden release from its archive.

    Supplies a context manager and file-type detection, which allows choosing
    the correct library for opening the archive automatically.
    """

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        if self.path.suffix == '.gz':
            self._context = TarFile.open(self.path, 'r:*')
        else:
            self._context = ZipFile(self.path, 'r')
        self.validate()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self) -> None:
        self.close()

    @property
    def files(self) -> List[str]:
        """Return a list of files present in the archive.

        Depending on the file extension, we choose the correct method to access
        this list.
        """
        if self.path.suffix == '.gz':
            return self._context.getnames()
        else:
            return self._context.namelist()

    @property
    def binary(self) -> str:
        """Return the name of the first file of our list of files.

        Since the archive must only contain a single file, this is automatically
        assumed to be our binary; this assumption *is not* checked for correctness.
        """
        return self.files[0]

    def validate(self) -> None:
        """Confirm there is only one file present in the archive.

        :raises ValueError: if the archive has an unexpected layout.
        """
        if len(self.files) != 1:
            raise ValueError(
                f'Release archive has unexpected content. '
                f'Expected 1 file, found {len(self.files)}: {", ".join(self.files)}',
            )

    def unpack(self, target_dir: pathlib.Path) -> pathlib.Path:
        """Unpack this release's archive to the given `target_dir`.

        We also set the x bit on the extracted binary.
        """
        self._context.extract(self.binary, target_dir)
        target_dir.chmod(0o770)
        return target_dir

    def close(self):
        """Close the context, if possible."""
        if self._context and hasattr(self._context, 'close'):
            self._context.close()


class Release:
    """Represents a single Raiden release, its version and binary's path.

    If the binary for the version is not present on the local machine, it can
    be downloaded using the :meth:`Release.download` method.
    """

    def __init__(self, version: Union[str, pathlib.Path]) -> None:
        #: Holds the original version value; this should not be changed.
        self._version = version

        #: Path to the binary on the local machine.
        self.binary = None

        #: Path to the archive on the local machine.
        self.archive = None

        if isinstance(self._version, pathlib.Path):
            if not version.exists():
                raise ValueError(
                    'Must supply a valid release version, '
                    'or an existing path to a binary or archive!',
                )
            if version.stem in ('.zip', '.gz'):
                # this is an archive
                self.archive = version
            if not is_executable(version):
                raise ValueError('Path to binary requires execution permission!')

    def __repr__(self) -> str:
        return f"Release(version={self._version!r})"

    def __str__(self) -> str:
        archive = self.archive.name if self.archive else None
        return f"Release <Version: {self.version} | Archive: {archive} | " \
            f"installed={self.binary_exists_locally}>"

    @property
    def version(self) -> str:
        """Return the Raiden release version.

        This constructs the version string from the internal :attr:`Release._version`
        attribute and does one of two things:

            1. Fetches the latest release version if the attributes value
                is 'latest', and returns it.

            or

            2. Checks if the value starts with a 'v' and strips it, modifying
                `version` in place; then returns it.
        """
        version = self._version
        if version.lower() == 'latest':
            version = get_latest_release()

        if version.startswith('v'):
            return version.lstrip('v')
        return version

    @property
    def binary_exists_locally(self) -> bool:
        """Return True if we found an *executable* binary path for :attr:`Release.binary`."""
        return self.binary.exists() and is_executable(self.binary)

    def download(self, target_folder: Union[str, pathlib.Path], overwrite=False) -> pathlib.Path:
        """Download this release's binary from our servers to the given `target_folder`."""
        target_file = RELEASE_ARCHIVE_NAME_TEMPLATE.format(version=self.version)

        download_destination = pathlib.Path(target_folder).joinpath(target_file)

        if download_destination.exists():
            if not overwrite:
                return download_destination
            download_destination.unlink()

        url = RAIDEN_RELEASES_URL + target_file

        with requests.get(url, stream=True) as resp:
            log.debug('Downloading Raiden release', release_file_name=target_file)
            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError as e:
                raise ValueError(
                    f"Can't download release file {target_file}!",
                ) from e

        with download_destination.open('wb') as release_file:
            shutil.copyfileobj(resp.raw, release_file)

        self.archive = download_destination
        return download_destination

    def unpack_archive(self, target_dir: pathlib.Path, overwrite=False) -> pathlib.Path:
        """Unpack the Release archive and return the path to the extracted binary."""
        with ReleaseArchive(target_dir) as archive:
            bin_file_path = target_dir.joinpath(archive.binary)
            if not bin_file_path.exists() or overwrite:
                log.debug(
                    'Extracting Raiden binary',
                    release_file_name=self.archive.name,
                    bin_file_name=bin_file_path.name,
                )
                self.binary = archive.unpack(bin_file_path)
            return bin_file_path

    def install(self, target_dir: pathlib.Path, overwrite=False) -> pathlib.Path:
        """Install the binary on the local machine from this archive.

        :param target_dir: The target path to install the binary to.
        :param overwrite: whether or not we should overwrite existing files.
        """
        if self.archive is None or not self.archive.exists():
            raise ValueError('Must download archive first!')
        if not overwrite and self.binary_exists_locally:
            return self.binary
        extracted_bin_path = self.unpack_archive(target_dir, overwrite)
        return extracted_bin_path

    def uninstall(self) -> None:
        """Remove the binary linked to this release, if it exists locally."""
        if self.binary and self.binary.exists():
            self.binary.unlink()
        self.binary = None

    def remove(self) -> None:
        """Remove the archive linked to this release, if it exists locally."""
        if self.archive and self.archive.exists():
            self.archive.unlink()
        self.archive = None

    def purge(self) -> None:
        """Remove the binary and archive linked to this release."""
        self.uninstall()
        self.remove()


class ReleaseManager:
    """Administration interface for release management.

    Capable of managing several Raiden releases, represented as
    :cls:`Release` instances.
    """

    def __init__(self, cache_path: pathlib.Path):
        self._releases = {}
        self._cache_path = cache_path

    @property
    def download_path(self) -> pathlib.Path:
        """Return the download directory path.

        If this does not exist yet, it will be created on the fly.
        """
        path = self._cache_path.joinpath('downloads')
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def bin_path(self) -> pathlib.Path:
        """Return the binary directory path.

        If this does not exist yet, it will be created on the fly.
        """
        path = self._cache_path.joinpath('bin')
        path.mkdir(exist_ok=True, parents=True)
        return path

    @property
    def releases(self) -> Dict[str, Release]:
        """Return a version-to-release mapping containing all known versions."""
        return self._releases

    @property
    def installed(self) -> Dict[str, Release]:
        """Return a version-to-release mapping containing all installed versions."""
        return {
            version: release for version, release in self._releases.items()
            if release.binary_exists_locally
        }

    def install(self, release: Union[Release, str], overwrite=False) -> Tuple[str, pathlib.Path]:
        """Install the given `release` on this machine, downloading it if necessary."""
        if isinstance(release, str):
            # we assume this is a version number/string; if it isn't, the operation will fail.
            release = Release(release)
        release.download(self.download_path, overwrite)
        release.install(self.bin_path, overwrite)

        self._releases[release.version] = release

        return release.version, release.binary

    def uninstall(self, version) -> None:
        """Uninstall the release with the given `version`."""
        release = self._releases[version]
        release.uninstall()

    def purge(self, cached=False) -> None:
        """Remove all releases registered with this ReleaseManager instance.

        If `cached` is truthy, we also remove the archive file from the local
        machine associated with each release, if present.
        """
        for release in self._releases.values():
            if cached:
                release.purge()
            else:
                release.uninstall()
        self._releases = {}
