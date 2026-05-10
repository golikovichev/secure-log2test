"""secure-log2test: convert Kibana API log exports into runnable pytest suites."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("secure-log2test")
except PackageNotFoundError:
    # Running from a source checkout without an installed distribution.
    __version__ = "0.0.0+unknown"
