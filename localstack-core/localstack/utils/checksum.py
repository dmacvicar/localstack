import hashlib
import logging
import os
import re
import tempfile
from abc import ABC, abstractmethod

from localstack.utils.files import load_file, rm_rf

# Setup logger
LOG = logging.getLogger(__name__)


class ChecksumException(Exception):
    """Base exception for checksum errors."""

    pass


class ChecksumFormat(ABC):
    """Abstract base class for checksum format parsers."""

    @abstractmethod
    def can_parse(self, content: str) -> bool:
        """
        Check if this parser can handle the given content.

        :param content: The content to check
        :return: True if parser can handle content, False otherwise
        """
        pass

    @abstractmethod
    def parse(self, content: str) -> dict[str, str]:
        """
        Parse the content and return filename to checksum mapping.

        :param content: The content to parse
        :return: Dictionary mapping filenames to checksums
        """
        pass


class StandardFormat(ChecksumFormat):
    """
    Handles standard checksum format.

    Supports formats like:

    * ``checksum  filename``
    * ``checksum *filename``
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        for line in lines[:5]:  # Check first 5 lines
            if re.match(r"^[a-fA-F0-9]{32,128}\s+\S+", line.strip()):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Match: checksum (whitespace) filename
            match = re.match(r"^([a-fA-F0-9]{32,128})\s+(\*?)(.+)$", line)
            if match:
                checksum, star, filename = match.groups()
                checksums[filename.strip()] = checksum.lower()

        return checksums


class BSDFormat(ChecksumFormat):
    """
    Handles BSD-style checksum format.

    Format: ``SHA512 (filename) = checksum``
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        for line in lines[:5]:
            if re.match(r"^(MD5|SHA1|SHA256|SHA512)\s*\(.+\)\s*=\s*[a-fA-F0-9]+", line):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Match: ALGORITHM (filename) = checksum
            match = re.match(r"^(MD5|SHA1|SHA256|SHA512)\s*\((.+)\)\s*=\s*([a-fA-F0-9]+)$", line)
            if match:
                algo, filename, checksum = match.groups()
                checksums[filename.strip()] = checksum.lower()

        return checksums


class MavenSingleFileChecksumFormat(ChecksumFormat):
    """
    Handles Maven-style single checksum files (.sha1, .sha256, .md5).

    Format: Just a single checksum value on one line:
    * ``abcdef123456...``
    """

    def can_parse(self, content: str) -> bool:
        content = content.strip()
        lines = content.split("\n")
        if len(lines) != 1:  # Must be exactly one line
            return False

        line = lines[0].strip()
        # Match: only hex string, no filename
        return bool(re.match(r"^[a-fA-F0-9]{32,128}$", line))

    def parse(self, content: str) -> dict[str, str]:
        content = content.strip()
        line = content.split("\n")[0].strip()

        if re.match(r"^[a-fA-F0-9]{32,128}$", line):
            return {"__SINGLE_FILE__": line.lower()}
        return {}


class ApacheBSDFormat(ChecksumFormat):
    """
    Handles Apache's BSD-style format with split checksums.

    Format::

        filename: CHECKSUM_PART1
                 CHECKSUM_PART2
                 CHECKSUM_PART3
    """

    def can_parse(self, content: str) -> bool:
        lines = content.strip().split("\n")
        if lines and ":" in lines[0]:
            # Check if it looks like filename: hex_data
            parts = lines[0].split(":", 1)
            if len(parts) == 2 and re.search(r"[a-fA-F0-9\s]+", parts[1]):
                return True
        return False

    def parse(self, content: str) -> dict[str, str]:
        checksums = {}
        lines = content.strip().split("\n")

        current_file = None
        checksum_parts = []

        for line in lines:
            if ":" in line and not line.startswith(" "):
                # New file entry
                if current_file and checksum_parts:
                    # Save previous file's checksum
                    full_checksum = "".join(checksum_parts).replace(" ", "").lower()
                    if re.match(r"^[a-fA-F0-9]+$", full_checksum):
                        checksums[current_file] = full_checksum

                # Start new file
                parts = line.split(":", 1)
                current_file = parts[0].strip()
                checksum_part = parts[1].strip()
                checksum_parts = [checksum_part]
            elif line.strip() and current_file:
                # Continuation of checksum
                checksum_parts.append(line.strip())

        # Don't forget the last file
        if current_file and checksum_parts:
            full_checksum = "".join(checksum_parts).replace(" ", "").lower()
            if re.match(r"^[a-fA-F0-9]+$", full_checksum):
                checksums[current_file] = full_checksum

        return checksums


class ChecksumParser:
    """Main parser that tries different checksum formats."""

    def __init__(self) -> None:
        """Initialize parser with available format parsers."""
        self.formats = [
            MavenSingleFileChecksumFormat(),  # Try Maven single file first
            StandardFormat(),
            BSDFormat(),
            ApacheBSDFormat(),
        ]

    def parse(self, content: str) -> dict[str, str]:
        """
        Try each format parser until one works.

        :param content: The content to parse
        :return: Dictionary mapping filenames to checksums
        """
        for format_parser in self.formats:
            if format_parser.can_parse(content):
                result = format_parser.parse(content)
                if result:
                    return result

        return {}


def parse_checksum_file_from_url(checksum_url: str) -> dict[str, str]:
    """
    Parse a SHA checksum file from a URL using multiple format parsers.

    DEPRECATED: This function contains download logic and should not be used in new code.
    Use the installer checksum resolution methods instead.

    :param checksum_url: URL of the checksum file
    :return: Dictionary mapping filenames to checksums
    """
    # import here to avoid circular dependency issues
    from localstack.utils.http import download

    checksum_name = os.path.basename(checksum_url)
    checksum_path = os.path.join(tempfile.gettempdir(), checksum_name)
    try:
        download(checksum_url, checksum_path)
        checksum_content = load_file(checksum_path)

        parser = ChecksumParser()
        checksums = parser.parse(checksum_content)

        return checksums
    finally:
        rm_rf(checksum_path)


def detect_algorithm_from_checksum(checksum: str) -> str:
    """
    Detect hash algorithm based on checksum length.

    :param checksum: The checksum string
    :return: Algorithm name
    """
    checksum_length = len(checksum)
    if checksum_length == 32:
        return "md5"
    elif checksum_length == 40:
        return "sha1"
    elif checksum_length == 64:
        return "sha256"
    elif checksum_length == 128:
        return "sha512"
    else:
        raise ChecksumException(f"Unsupported checksum length: {checksum_length}")


def calculate_file_checksum(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate checksum of a local file.

    :param file_path: Path to the file
    :param algorithm: Hash algorithm to use (defaults to 'sha256')
    :return: Calculated checksum as hexadecimal string

    note: Supported algorithms: 'md5', 'sha1', 'sha256', 'sha512'
    """
    hash_func = getattr(hashlib, algorithm)()

    with open(file_path, "rb") as f:
        # Read file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def verify_file_checksum(file_path: str, expected_checksum: str) -> bool:
    """
    Verify a local file against an expected checksum.
    Algorithm is automatically detected from checksum length.

    :param file_path: Path to the local file to verify
    :param expected_checksum: Expected checksum
    :return: True if verification succeeds
    :raises ChecksumException: If checksum verification fails
    """
    algorithm = detect_algorithm_from_checksum(expected_checksum)
    calculated_checksum = calculate_file_checksum(file_path, algorithm)

    if calculated_checksum != expected_checksum.lower():
        raise ChecksumException(
            f"Checksum mismatch for {file_path}: calculated {calculated_checksum}, expected {expected_checksum}"
        )

    return True


def find_checksum_in_checksum_url(filename: str, checksum_url: str) -> str | None:
    """
    Find checksum for the given filename from an online checksum file.

    :param filename: The filename to find checksum for
    :param checksum_url: URL of the checksum file
    :return: Resolved checksum string, or None if not found
    """
    try:
        import tempfile

        from localstack.utils.files import load_file, rm_rf

        checksum_name = os.path.basename(checksum_url)
        checksum_path = os.path.join(tempfile.gettempdir(), checksum_name)

        try:
            # Import here to avoid circular dependency
            from localstack.utils.http import download

            LOG.debug("Fetching checksums from %s...", checksum_url)
            download(checksum_url, checksum_path)
            checksum_content = load_file(checksum_path)

            if not checksum_content:
                LOG.warning("Empty checksum file from %s", checksum_url)
                return None

            parser = ChecksumParser()
            checksums = parser.parse(checksum_content)

            if not checksums:
                LOG.warning("No checksums found in %s", checksum_url)
                return None

            # Single file format (like Maven)
            if "__SINGLE_FILE__" in checksums:
                return checksums["__SINGLE_FILE__"]

            if filename in checksums:
                return checksums[filename]

            # Try with different path variations
            possible_names = [
                filename,
                os.path.basename(filename),  # just filename without path
                filename.replace("\\", "/"),  # Unix-style paths
                filename.replace("/", "\\"),  # Windows-style paths
            ]

            for name in possible_names:
                if name in checksums:
                    return checksums[name]

            # If still not found, try basename matching against all checksums
            basename = os.path.basename(filename)
            for file_in_checksum, checksum in checksums.items():
                if os.path.basename(file_in_checksum) == basename:
                    return checksum

            LOG.warning("Checksum for %s not found in %s", filename, checksum_url)
            return None

        finally:
            rm_rf(checksum_path)

    except Exception as e:
        LOG.warning("Failed to resolve checksum from %s: %s", checksum_url, e)
        return None
