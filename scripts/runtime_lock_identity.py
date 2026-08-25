#!/usr/bin/env python3
"""Return the reboot-stable identity of an opened deployment lock."""

import ctypes
import os
import pathlib
import struct
import sys


class _AttrList(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_ushort),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


_ATTR_BIT_MAP_COUNT = 5
_ATTR_CMN_OBJPERMANENTID = 0x00000040
_ATTR_VOL_UUID = 0x00040000
_ATTR_VOL_INFO = 0x80000000


def _darwin_attribute(fd, *, common=0, volume=0, size):
    attributes = _AttrList(
        _ATTR_BIT_MAP_COUNT,
        0,
        common,
        volume,
        0,
        0,
        0,
    )
    buffer = ctypes.create_string_buffer(size)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.fgetattrlist(
        fd,
        ctypes.byref(attributes),
        buffer,
        len(buffer),
        0,
    )
    if result != 0:
        raise OSError(ctypes.get_errno(), "fgetattrlist failed")
    raw = buffer.raw
    if struct.unpack_from("=I", raw)[0] != size:
        raise OSError("fgetattrlist returned an unexpected attribute size")
    return raw[4:size]


def descriptor_identity(fd, *, platform=None):
    platform = sys.platform if platform is None else platform
    metadata = os.fstat(fd)
    if platform == "darwin":
        object_id = _darwin_attribute(
            fd,
            common=_ATTR_CMN_OBJPERMANENTID,
            size=12,
        )
        volume_uuid = _darwin_attribute(
            fd,
            volume=_ATTR_VOL_INFO | _ATTR_VOL_UUID,
            size=20,
        )
        object_number, generation = struct.unpack("=II", object_id)
        if object_number == 0 or volume_uuid == bytes(16):
            raise OSError("persistent filesystem identity is unavailable")
        return (
            f"darwin-volume-object-v1:{volume_uuid.hex()}:{object_number}:{generation}"
        )
    if platform.startswith("linux"):
        return f"linux-device-inode-v1:{metadata.st_dev}:{metadata.st_ino}"
    raise OSError(f"unsupported runtime-lock platform: {platform}")


def path_identity(path):
    path = pathlib.Path(path)
    fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        return descriptor_identity(fd)
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 2 or not pathlib.Path(sys.argv[1]).is_absolute():
        raise SystemExit(f"usage: {sys.argv[0]} ABSOLUTE_PATH")
    try:
        print(path_identity(sys.argv[1]))
    except OSError as error:
        raise SystemExit(f"runtime lock identity: {error}") from error


if __name__ == "__main__":
    main()
