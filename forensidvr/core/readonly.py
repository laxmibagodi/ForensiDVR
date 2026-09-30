"""Read-only enforcement for evidence (hard requirement #1).

Two layers:

1. :func:`open_readonly` / :class:`ReadOnlyFile` open evidence with ``O_RDONLY`` only and expose
   no write methods. All image readers use these.
2. :class:`WriteBlocker` is a *software* write-blocker: while active it intercepts Python-level
   write/delete/rename/truncate/chmod calls that target protected paths and raises
   :class:`~forensidvr.core.errors.WriteBlockedError`.

The software blocker is defence-in-depth against programming errors inside this process. It is
not a substitute for a hardware write-blocker when imaging a physical disk (see
docs/sop/acquisition.md).
"""

from __future__ import annotations

import builtins
import errno
import io
import os
import shutil
import stat
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar

from forensidvr.core.errors import WriteBlockedError

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _readonly_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    return flags


def open_readonly(path: str | os.PathLike[str]) -> int:
    """Open ``path`` read-only and return a file descriptor.

    Tries ``O_NOATIME`` first (avoids updating access time on the source) and falls back when the
    kernel refuses it (``EPERM`` for files not owned by the caller).
    """
    base = _readonly_flags()
    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            fd = os.open(path, base | noatime)
        except PermissionError:
            fd = os.open(path, base)
    else:
        fd = os.open(path, base)
    assert_fd_readonly(fd)
    return fd


def assert_fd_readonly(fd: int) -> None:
    """Raise :class:`WriteBlockedError` unless ``fd`` was opened read-only."""
    try:
        import fcntl

        mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    except (ImportError, OSError):  # pragma: no cover - non-POSIX
        return
    if mode != os.O_RDONLY:
        raise WriteBlockedError(f"file descriptor {fd} is not read-only")


def fd_size(fd: int) -> int:
    """Size of a regular file or block device behind ``fd``."""
    st = os.fstat(fd)
    if stat.S_ISREG(st.st_mode):
        return st.st_size
    return os.lseek(fd, 0, os.SEEK_END)


class ReadOnlyFile:
    """Read-only positional file handle. Has no write/truncate/flush methods by design."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._fd: int | None = open_readonly(self.path)
        self.size = fd_size(self._fd)

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise ValueError("I/O operation on closed file")
        return self._fd

    def read_at(self, offset: int, length: int) -> bytes:
        """Positional read; never moves a shared file offset (thread safe)."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        out = bytearray()
        while len(out) < length:
            chunk = os.pread(self.fd, length - len(out), offset + len(out))
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def write(self, *_args: Any, **_kwargs: Any) -> None:
        raise WriteBlockedError(f"{self.path} is opened read-only")

    truncate = write

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> ReadOnlyFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _mode_writes(mode: str) -> bool:
    return any(c in mode for c in "wax+")


class WriteBlocker:
    """Software write-blocker for a set of evidence paths (process-wide while active).

    Usage::

        with WriteBlocker([image_path]):
            run_analysis(image_path)

    Nested/concurrent blockers are supported; protected sets are unioned.
    """

    _lock = threading.RLock()
    _active: ClassVar[list[WriteBlocker]] = []
    _originals: ClassVar[dict[str, Any]] = {}

    def __init__(self, paths: Iterable[str | os.PathLike[str]]) -> None:
        self.paths = frozenset(self._norm(p) for p in paths)
        self.blocked_attempts: list[str] = []

    @staticmethod
    def _norm(path: str | os.PathLike[str] | int) -> str:
        if isinstance(path, int):
            return ""
        return os.path.realpath(os.fspath(path))

    @classmethod
    def is_protected(cls, path: Any) -> bool:
        """True if ``path`` is protected by any active blocker."""
        if isinstance(path, int) or path is None:
            return False
        try:
            norm = cls._norm(path)
        except TypeError:
            return False
        with cls._lock:
            return any(norm in b.paths for b in cls._active)

    @classmethod
    def _deny(cls, op: str, path: Any) -> None:
        msg = f"write-blocker: {op} denied on protected evidence {os.fspath(path)!s}"
        with cls._lock:
            for b in cls._active:
                b.blocked_attempts.append(msg)
        raise WriteBlockedError(errno.EACCES, msg)

    @classmethod
    def _install(cls) -> None:
        o = cls._originals
        o["builtins.open"] = builtins.open
        o["io.open"] = io.open
        o["os.open"] = os.open
        for name in (
            "remove",
            "unlink",
            "rename",
            "replace",
            "truncate",
            "chmod",
            "utime",
            "rmdir",
            "chown",
        ):
            if hasattr(os, name):
                o[f"os.{name}"] = getattr(os, name)
        o["shutil.rmtree"] = shutil.rmtree
        o["shutil.move"] = shutil.move

        orig_open = o["builtins.open"]

        def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if _mode_writes(mode) and cls.is_protected(file):
                cls._deny(f"open(mode={mode!r})", file)
            return orig_open(file, mode, *args, **kwargs)

        orig_os_open = o["os.open"]

        def guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if flags & _WRITE_FLAGS and cls.is_protected(path):
                cls._deny("os.open(write flags)", path)
            fd: int = orig_os_open(path, flags, *args, **kwargs)
            return fd

        def guard_path_op(name: str, nargs: int) -> Callable[..., Any]:
            orig = o[name]

            def guarded(*args: Any, **kwargs: Any) -> Any:
                for p in args[:nargs]:
                    if cls.is_protected(p):
                        cls._deny(name, p)
                return orig(*args, **kwargs)

            return guarded

        builtins.open = guarded_open
        io.open = guarded_open
        os.open = guarded_os_open
        for key in list(o):
            if key.startswith("os.") and key != "os.open":
                nargs = 2 if key in ("os.rename", "os.replace") else 1
                setattr(os, key[3:], guard_path_op(key, nargs))
        shutil.rmtree = guard_path_op("shutil.rmtree", 1)  # type: ignore[assignment]
        shutil.move = guard_path_op("shutil.move", 2)

    @classmethod
    def _uninstall(cls) -> None:
        o = cls._originals
        builtins.open = o["builtins.open"]
        io.open = o["io.open"]
        for key, fn in o.items():
            if key.startswith("os."):
                setattr(os, key[3:], fn)
        shutil.rmtree = o["shutil.rmtree"]
        shutil.move = o["shutil.move"]
        o.clear()

    def __enter__(self) -> WriteBlocker:
        with self._lock:
            if not self._active:
                self._install()
            self._active.append(self)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        with self._lock:
            self._active.remove(self)
            if not self._active:
                self._uninstall()
