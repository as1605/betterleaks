"""Internal C ABI and Windows CLI fallback bindings for Betterleaks."""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import json
import os
import platform
import subprocess
import sys
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from betterleaks.cli import get_binary_path
from betterleaks.models import BetterleaksError

_EXPECTED_ABI_VERSION = 1
_DEFAULT_MAX_INPUT_BYTES = 8 << 20
_MAX_INPUT_BYTES = 64 << 20
_DEFAULT_MAX_FINDINGS = 10_000
_MAX_FINDINGS = 100_000
_MAX_WORKERS = 1024
_SCANNER_CACHE_MAX_SIZE = 16

_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".tbz2",
    ".xz",
    ".txz",
    ".zst",
    ".tzst",
    ".lz4",
    ".rar",
    ".7z",
    ".br",
    ".lz",
    ".sz",
    ".zz",
)

_ARCHIVE_MAGIC_PREFIXES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b'\x04"M\x18',
)


class _BlBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def _candidate_library_names() -> List[str]:
    system = platform.system().lower()
    if system == "darwin":
        return ["libbetterleaks_ffi.dylib", "libbetterleaks_ffi.so"]
    if system == "windows":
        return ["libbetterleaks_ffi.dll", "betterleaks_ffi.dll"]
    return ["libbetterleaks_ffi.so"]


def _native_target_dir_name() -> Optional[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        return (
            "aarch64-apple-darwin"
            if machine in ("arm64", "aarch64")
            else "x86_64-apple-darwin"
        )
    if system == "linux":
        return (
            "aarch64-unknown-linux-gnu"
            if machine in ("arm64", "aarch64")
            else "x86_64-unknown-linux-gnu"
        )
    return None


def _find_library() -> Optional[str]:
    """Locate the compiled Betterleaks FFI shared library, or None if unavailable."""
    custom_path = os.environ.get("BETTERLEAKS_LIB_PATH")
    if custom_path:
        if os.path.isfile(custom_path):
            return custom_path
        raise BetterleaksError(
            f"BETTERLEAKS_LIB_PATH points to a missing file: {custom_path}"
        )

    candidate_names = _candidate_library_names()

    custom_dir = os.environ.get("BETTERLEAKS_LIB_DIR")
    if custom_dir:
        for name in candidate_names:
            candidate = os.path.join(custom_dir, name)
            if os.path.isfile(candidate):
                return candidate
        raise BetterleaksError(
            f"Could not find {candidate_names} in BETTERLEAKS_LIB_DIR={custom_dir}"
        )

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for name in candidate_names:
        candidate = os.path.join(pkg_dir, name)
        if os.path.isfile(candidate):
            return candidate

    target = _native_target_dir_name()
    if target:
        repo_root = os.path.abspath(os.path.join(pkg_dir, "..", "..", "..", ".."))
        for name in candidate_names:
            candidate = os.path.join(repo_root, "dist", "native", target, "lib", name)
            if os.path.isfile(candidate):
                return candidate

    return None


def _is_recognized_archive(file_path: str) -> bool:
    lower = file_path.lower()
    if lower.endswith(_ARCHIVE_EXTENSIONS):
        return True
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return False
    if any(head.startswith(prefix) for prefix in _ARCHIVE_MAGIC_PREFIXES):
        return True
    # POSIX ustar tar magic at byte offset 257.
    return len(head) >= 263 and head[257:263] == b"ustar\x00"


def _validate_scanner_limits(
    workers: int,
    max_decode_depth: int,
    max_input_bytes: Optional[int],
    max_findings: Optional[int],
) -> Tuple[int, int]:
    if workers < 0 or workers > _MAX_WORKERS:
        raise BetterleaksError(f"workers must be between 0 and {_MAX_WORKERS}")
    if max_decode_depth < 0:
        raise BetterleaksError("max_decode_depth must be non-negative")
    effective_input = (
        _DEFAULT_MAX_INPUT_BYTES if max_input_bytes is None else max_input_bytes
    )
    if effective_input < 1 or effective_input > _MAX_INPUT_BYTES:
        raise BetterleaksError(
            f"max_input_bytes must be between 1 and {_MAX_INPUT_BYTES}"
        )
    effective_findings = _DEFAULT_MAX_FINDINGS if max_findings is None else max_findings
    if effective_findings < 1 or effective_findings > _MAX_FINDINGS:
        raise BetterleaksError(f"max_findings must be between 1 and {_MAX_FINDINGS}")
    return effective_input, effective_findings


class _NativeLibrary:
    """Thin ctypes wrapper around bindings/c/betterleaks.h."""

    def __init__(self, lib_path: str) -> None:
        self._lib = ctypes.CDLL(lib_path)

        self._lib.bl_abi_version.argtypes = []
        self._lib.bl_abi_version.restype = ctypes.c_uint32

        self._lib.bl_scanner_new.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_new.restype = ctypes.c_int32

        self._lib.bl_scanner_scan.argtypes = [
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(_BlBuffer),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_scan.restype = ctypes.c_int32

        self._lib.bl_scanner_scan_file.argtypes = [
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(_BlBuffer),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_scan_file.restype = ctypes.c_int32

        self._lib.bl_scanner_free.argtypes = [ctypes.c_uint64]
        self._lib.bl_scanner_free.restype = ctypes.c_int32

        self._lib.bl_buffer_free.argtypes = [_BlBuffer]
        self._lib.bl_buffer_free.restype = None

        abi = self._lib.bl_abi_version()
        if abi != _EXPECTED_ABI_VERSION:
            raise BetterleaksError(
                f"Incompatible Betterleaks native ABI version: expected {_EXPECTED_ABI_VERSION}, got {abi}"
            )

    @staticmethod
    def _decode_buffer(buf: _BlBuffer) -> bytes:
        if not buf.data or buf.len == 0:
            return b""
        return ctypes.string_at(buf.data, buf.len)

    def _raise_error(self, status: int, err_buf: _BlBuffer) -> None:
        raw = self._decode_buffer(err_buf)
        msg = raw.decode("utf-8", errors="replace").strip() if raw else ""
        raise BetterleaksError(msg or f"Betterleaks native error (status {status})")

    def new_scanner(self, options_json: Optional[bytes]) -> int:
        handle = ctypes.c_uint64()
        err_buf = _BlBuffer()
        try:
            opt_ptr = options_json if options_json else None
            opt_len = len(options_json) if options_json else 0
            status = self._lib.bl_scanner_new(
                opt_ptr, opt_len, ctypes.byref(handle), ctypes.byref(err_buf)
            )
            if status != 0:
                self._raise_error(status, err_buf)
            return int(handle.value)
        finally:
            self._lib.bl_buffer_free(err_buf)

    def scan_bytes(
        self,
        handle: int,
        data: bytes,
        attributes_json: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        res_buf = _BlBuffer()
        err_buf = _BlBuffer()
        try:
            data_ptr = data if data else None
            data_len = len(data)
            attr_ptr = attributes_json if attributes_json else None
            attr_len = len(attributes_json) if attributes_json else 0
            status = self._lib.bl_scanner_scan(
                handle,
                data_ptr,
                data_len,
                attr_ptr,
                attr_len,
                ctypes.byref(res_buf),
                ctypes.byref(err_buf),
            )
            if status != 0:
                self._raise_error(status, err_buf)
            raw = self._decode_buffer(res_buf)
            if not raw:
                raise BetterleaksError("Empty response from Betterleaks native library")
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise BetterleaksError(
                    f"Failed to parse response from Betterleaks library: {err}"
                ) from err
        finally:
            self._lib.bl_buffer_free(res_buf)
            self._lib.bl_buffer_free(err_buf)

    def scan_file(self, handle: int, path_bytes: bytes) -> Dict[str, Any]:
        res_buf = _BlBuffer()
        err_buf = _BlBuffer()
        try:
            status = self._lib.bl_scanner_scan_file(
                handle,
                path_bytes,
                len(path_bytes),
                ctypes.byref(res_buf),
                ctypes.byref(err_buf),
            )
            if status != 0:
                self._raise_error(status, err_buf)
            raw = self._decode_buffer(res_buf)
            if not raw:
                raise BetterleaksError("Empty response from Betterleaks native library")
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise BetterleaksError(
                    f"Failed to parse response from Betterleaks library: {err}"
                ) from err
        finally:
            self._lib.bl_buffer_free(res_buf)
            self._lib.bl_buffer_free(err_buf)

    def free_scanner(self, handle: int) -> None:
        self._lib.bl_scanner_free(handle)


class _CLIBacking:
    """Subprocess fallback using the bundled betterleaks CLI (used on Windows)."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        if config_path is not None:
            if not config_path or "\x00" in config_path:
                raise BetterleaksError(
                    "config_path must be a non-empty path without NUL"
                )
            if config_toml is None and not os.path.isfile(config_path):
                raise BetterleaksError(
                    f"failed to load config from {config_path}: file not found"
                )
        effective_input, effective_findings = _validate_scanner_limits(
            workers, max_decode_depth, max_input_bytes, max_findings
        )
        self._config_path = config_path
        self._config_toml = config_toml
        self._workers = workers
        self._max_decode_depth = max_decode_depth
        self._max_input_bytes = effective_input
        self._max_findings = effective_findings
        self._closed = False
        self._lock = threading.Lock()

    def _ensure_open(self) -> None:
        with self._lock:
            if self._closed:
                raise BetterleaksError("Scanner is closed")

    def _build_env_and_args(self) -> Tuple[Dict[str, str], List[str]]:
        env = os.environ.copy()
        # Keep API scans strictly detection-only and prevent inherited CLI env vars
        # from overriding explicit Scanner configuration.
        for var in (
            "BETTERLEAKS_VALIDATE",
            "BETTERLEAKS_ANALYZE",
            "BETTERLEAKS_CONFIG",
            "BETTERLEAKS_CONFIG_TOML",
        ):
            env.pop(var, None)

        args: List[str] = [
            f"--max-decode-depth={self._max_decode_depth}",
        ]
        if self._workers > 0:
            args.append(f"--jobs={self._workers}")

        if self._config_toml is not None:
            env["BETTERLEAKS_CONFIG_TOML"] = self._config_toml
        elif self._config_path:
            args.extend(["-c", self._config_path])
        return env, args

    def _parse_cli_output(self, proc: subprocess.CompletedProcess) -> Dict[str, Any]:
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            raise BetterleaksError(
                err or f"betterleaks CLI exited with status {proc.returncode}"
            )
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return {"findings": []}
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as err:
            raise BetterleaksError(f"Failed to parse CLI JSON output: {err}") from err
        if isinstance(payload, list):
            result = {"findings": payload}
        elif isinstance(payload, dict):
            result = payload
        else:
            raise BetterleaksError(
                "Unexpected JSON output structure from betterleaks CLI"
            )

        findings = result.get("findings") or []
        if len(findings) > self._max_findings:
            raise BetterleaksError("scan exceeds max_findings")
        return result

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        self._ensure_open()
        encoded = content.encode("utf-8")
        if len(encoded) > self._max_input_bytes:
            raise BetterleaksError("input exceeds max_input_bytes")

        binary = get_binary_path()
        env, cfg_args = self._build_env_and_args()
        cmd = [
            binary,
            "stdin",
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
            *cfg_args,
        ]
        if attributes:
            for k, v in attributes.items():
                cmd.extend(["--set-attr", f"{k}={v}"])
        proc = subprocess.run(
            cmd,
            input=encoded,
            env=env,
            capture_output=True,
            check=False,
        )
        return self._parse_cli_output(proc)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        self._ensure_open()
        if not file_path or "\x00" in file_path:
            raise BetterleaksError("file_path must be a non-empty path without NUL")
        if not os.path.exists(file_path):
            raise BetterleaksError(f"failed to read file {file_path}: file not found")
        if not os.path.isfile(file_path):
            raise BetterleaksError("scan_file requires a regular file")
        if os.path.getsize(file_path) > self._max_input_bytes:
            raise BetterleaksError("file exceeds max_input_bytes")
        if _is_recognized_archive(file_path):
            raise BetterleaksError(
                "archive inputs are not supported by scan_file; use the CLI to scan archives"
            )

        binary = get_binary_path()
        env, cfg_args = self._build_env_and_args()
        cmd = [
            binary,
            file_path,
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "--max-archive-depth=0",
            "-o",
            "-",
            *cfg_args,
        ]
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            check=False,
        )
        data = self._parse_cli_output(proc)
        for finding in data.get("findings") or []:
            loc = finding.setdefault("location", {})
            if not loc.get("path"):
                loc["path"] = file_path
        return data

    def close(self) -> None:
        with self._lock:
            self._closed = True


class _NativeScannerBacking:
    """Handle-backed native scanner wrapping bindings/c."""

    def __init__(
        self,
        lib: _NativeLibrary,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        options: Dict[str, Any] = {}
        if config_toml is not None:
            options["config_toml"] = config_toml
        if config_path is not None:
            if not config_path or "\x00" in config_path:
                raise BetterleaksError(
                    "config_path must be a non-empty path without NUL"
                )
            options["config_path"] = config_path
        if workers:
            options["workers"] = workers
        if max_decode_depth:
            options["max_decode_depth"] = max_decode_depth
        if max_input_bytes is not None:
            options["max_input_bytes"] = max_input_bytes
        if max_findings is not None:
            options["max_findings"] = max_findings

        options_bytes = json.dumps(options).encode("utf-8") if options else None
        self._lib = lib
        self._handle: Optional[int] = lib.new_scanner(options_bytes)
        self._lock = threading.RLock()

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        encoded = content.encode("utf-8")
        attr_bytes = json.dumps(attributes).encode("utf-8") if attributes else None
        with self._lock:
            if self._handle is None:
                raise BetterleaksError("Scanner is closed")
            return self._lib.scan_bytes(self._handle, encoded, attr_bytes)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not file_path or "\x00" in file_path:
            raise BetterleaksError("file_path must be a non-empty path without NUL")
        encoded_path = os.fsencode(file_path)
        with self._lock:
            if self._handle is None:
                raise BetterleaksError("Scanner is closed")
            return self._lib.scan_file(self._handle, encoded_path)

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                handle = self._handle
                self._handle = None
                self._lib.free_scanner(handle)

    def __del__(self) -> None:
        if (
            getattr(self, "_handle", None) is not None
            and getattr(self, "_lib", None) is not None
        ):
            with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
                self.close()


_native_lib_instance: Optional[_NativeLibrary] = None
_native_lib_checked = False
_native_lib_lock = threading.Lock()

_default_scanner: Optional[Any] = None
_scanner_cache: OrderedDict[str, Any] = OrderedDict()
_scanner_cache_lock = threading.Lock()


def _get_native_library() -> Optional[_NativeLibrary]:
    global _native_lib_instance, _native_lib_checked
    if not _native_lib_checked:
        with _native_lib_lock:
            if not _native_lib_checked:
                lib_path = _find_library()
                if lib_path:
                    _native_lib_instance = _NativeLibrary(lib_path)
                elif sys.platform != "win32":
                    raise BetterleaksError(
                        "Could not find Betterleaks native shared library "
                        f"({_candidate_library_names()}). "
                        "Build the native library or set BETTERLEAKS_LIB_PATH / BETTERLEAKS_LIB_DIR."
                    )
                _native_lib_checked = True
    return _native_lib_instance


def create_backing(
    config_path: Optional[str] = None,
    config_toml: Optional[str] = None,
    workers: int = 0,
    max_decode_depth: int = 0,
    max_input_bytes: Optional[int] = None,
    max_findings: Optional[int] = None,
):
    lib = _get_native_library()
    if lib is not None:
        return _NativeScannerBacking(
            lib,
            config_path=config_path,
            config_toml=config_toml,
            workers=workers,
            max_decode_depth=max_decode_depth,
            max_input_bytes=max_input_bytes,
            max_findings=max_findings,
        )
    return _CLIBacking(
        config_path=config_path,
        config_toml=config_toml,
        workers=workers,
        max_decode_depth=max_decode_depth,
        max_input_bytes=max_input_bytes,
        max_findings=max_findings,
    )


def get_cached_backing(config_path: Optional[str] = None):
    global _default_scanner
    if config_path is None:
        if _default_scanner is not None:
            return _default_scanner
        with _scanner_cache_lock:
            if _default_scanner is None:
                _default_scanner = create_backing(config_path=None)
            return _default_scanner

    if not config_path or "\x00" in config_path:
        raise BetterleaksError("config_path must be a non-empty path without NUL")
    resolved_path = os.path.abspath(config_path)

    with _scanner_cache_lock:
        cached = _scanner_cache.get(resolved_path)
        if cached is not None:
            _scanner_cache.move_to_end(resolved_path)
            return cached

        backing = create_backing(config_path=resolved_path)
        _scanner_cache[resolved_path] = backing
        while len(_scanner_cache) > _SCANNER_CACHE_MAX_SIZE:
            _, evicted = _scanner_cache.popitem(last=False)
            with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
                evicted.close()
        return backing


def _cleanup_cached_scanners() -> None:
    global _default_scanner
    with _scanner_cache_lock:
        scanners = list(_scanner_cache.values())
        _scanner_cache.clear()
        if _default_scanner is not None:
            scanners.append(_default_scanner)
            _default_scanner = None
    for scanner in scanners:
        with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
            scanner.close()


atexit.register(_cleanup_cached_scanners)
