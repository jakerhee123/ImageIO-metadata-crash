#!/usr/bin/env python3
"""Graft crash1.jpg's malformed metadata onto an arbitrary JPEG.

The source JPEG's coding tables, frame/scan headers, entropy-coded bytes, and
EOI are copied byte-for-byte. Only selected APP1/APP2 metadata is replaced.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence, TypedDict

SOI, EOI, SOS = 0xD8, 0xD9, 0xDA
APP0, APP1, APP2, APP15, COM = 0xE0, 0xE1, 0xE2, 0xEF, 0xFE
EXIF_ID = b"Exif\x00\x00"
XMP_ID = b"http://ns.adobe.com/xap/1.0/\x00"
EXT_XMP_ID = b"http://ns.adobe.com/xmp/extension/\x00"
MPF_ID = b"MPF\x00"


class JpegError(ValueError):
    pass


@dataclass(frozen=True)
class Segment:
    marker: int
    raw: bytes
    payload: bytes
    offset: int


class BuildDetails(TypedDict):
    source_size: int
    output_size: int
    profile: str
    removed: list[str]
    injected: list[str]
    coding_stream_sha256: str
    advertised_second_image_offset: int | None


def parse_header(blob: bytes, label: str) -> tuple[list[Segment], bytes]:
    """Return pre-SOS segments and the untouched bytes from SOS onward."""
    if not blob.startswith(b"\xff\xd8"):
        raise JpegError(f"{label}: missing JPEG SOI marker")
    segments: list[Segment] = []
    pos = 2
    while pos < len(blob):
        start = pos
        if blob[pos] != 0xFF:
            raise JpegError(f"{label}: expected marker at offset 0x{pos:x}")
        while pos < len(blob) and blob[pos] == 0xFF:
            pos += 1
        if pos >= len(blob):
            raise JpegError(f"{label}: truncated marker at 0x{start:x}")
        marker = blob[pos]
        pos += 1
        if marker == SOS:
            if pos + 2 > len(blob):
                raise JpegError(f"{label}: truncated SOS length")
            length = int.from_bytes(blob[pos : pos + 2], "big")
            if length < 2 or pos + length > len(blob):
                raise JpegError(f"{label}: invalid SOS length {length}")
            return segments, blob[start:]
        if marker == EOI:
            raise JpegError(f"{label}: EOI appears before SOS")
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            segments.append(Segment(marker, blob[start:pos], b"", start))
            continue
        if pos + 2 > len(blob):
            raise JpegError(f"{label}: truncated segment length at 0x{start:x}")
        length = int.from_bytes(blob[pos : pos + 2], "big")
        if length < 2 or pos + length > len(blob):
            raise JpegError(f"{label}: bad segment length {length} at 0x{start:x}")
        end = pos + length
        segments.append(Segment(marker, blob[start:end], blob[pos + 2 : end], start))
        pos = end
    raise JpegError(f"{label}: no SOS marker")


def metadata_kind(segment: Segment) -> str | None:
    if segment.marker == APP1:
        if segment.payload.startswith(EXIF_ID):
            return "exif"
        if segment.payload.startswith(XMP_ID):
            return "xmp"
        if segment.payload.startswith(EXT_XMP_ID):
            return "extended-xmp"
    if segment.marker == APP2 and segment.payload.startswith(MPF_ID):
        return "mpf"
    return None


PROFILE_KINDS: dict[str, frozenset[str]] = {
    "gainmap": frozenset(("xmp", "extended-xmp", "mpf")),
    "xmp-only": frozenset(("xmp", "extended-xmp")),
    "mpf-only": frozenset(("mpf",)),
    "exif-only": frozenset(("exif",)),
    "all": frozenset(("exif", "xmp", "extended-xmp", "mpf")),
}


def collect_donor_segments(
    donor_segments: Sequence[Segment], wanted: frozenset[str]
) -> list[Segment]:
    selected = [s for s in donor_segments if metadata_kind(s) in wanted]
    found = {kind for s in selected if (kind := metadata_kind(s)) is not None}
    missing = sorted(wanted - found)
    if missing:
        raise JpegError("donor lacks metadata: " + ", ".join(missing))
    return selected


def injection_index(segments: Sequence[Segment]) -> int:
    index = 0
    while index < len(segments):
        marker = segments[index].marker
        if APP0 <= marker <= APP15 or marker == COM:
            index += 1
        else:
            break
    return index


def coding_digest(segments: Iterable[Segment], scan_and_tail: bytes) -> str:
    digest = hashlib.sha256()
    for segment in segments:
        if not (APP0 <= segment.marker <= APP15) and segment.marker != COM:
            digest.update(segment.raw)
    digest.update(scan_and_tail)
    return digest.hexdigest()


def u16(data: bytes | bytearray, offset: int, endian: str) -> int:
    return int(struct.unpack_from(endian + "H", data, offset)[0])


def u32(data: bytes | bytearray, offset: int, endian: str) -> int:
    return int(struct.unpack_from(endian + "I", data, offset)[0])


def patch_mpf(
    raw: bytes, marker_offset: int, output_size: int, missing_gap: int
) -> tuple[bytes, int]:
    """Move the MPF-advertised second image beyond EOF."""
    if len(raw) < 12 or raw[:2] != b"\xff\xe2" or raw[4:8] != MPF_ID:
        raise JpegError("selected donor data is not an MPF APP2 segment")
    if int.from_bytes(raw[2:4], "big") + 2 != len(raw):
        raise JpegError("MPF APP2 segment has inconsistent length")
    patched = bytearray(raw)
    tiff = 8
    byte_order = bytes(patched[tiff : tiff + 2])
    endian = "<" if byte_order == b"II" else ">" if byte_order == b"MM" else ""
    if not endian or u16(patched, tiff + 2, endian) != 42:
        raise JpegError("invalid MPF TIFF header")
    ifd = tiff + u32(patched, tiff + 4, endian)
    if ifd + 2 > len(patched):
        raise JpegError("MPF IFD is outside APP2")
    entry_count = u16(patched, ifd, endian)
    table: int | None = None
    table_size = 0
    for index in range(entry_count):
        entry = ifd + 2 + index * 12
        if entry + 12 > len(patched):
            raise JpegError("truncated MPF IFD entry")
        if u16(patched, entry, endian) == 0xB002:
            table_size = u32(patched, entry + 4, endian)
            table = tiff + u32(patched, entry + 8, endian)
            break
    if table is None or table_size < 32 or table + 32 > len(patched):
        raise JpegError("MPF directory lacks two complete MP entries")
    second_absolute = output_size + missing_gap
    second_relative = second_absolute - (marker_offset + tiff)
    if not (0 <= second_absolute <= 0xFFFFFFFF):
        raise JpegError("advertised primary size does not fit MPF")
    if not (0 <= second_relative <= 0xFFFFFFFF):
        raise JpegError("advertised second offset does not fit MPF")
    # MP Entry: attributes[4], size[4], data offset[4], dependencies[4].
    struct.pack_into(endian + "I", patched, table + 4, second_absolute)
    struct.pack_into(endian + "I", patched, table + 24, second_relative)
    return bytes(patched), second_absolute


def build_output(
    source: bytes,
    donor: bytes,
    profile: str,
    mpf_offset_mode: str,
    missing_gap: int,
) -> tuple[bytes, BuildDetails]:
    source_segments, source_tail = parse_header(source, "source")
    if b"\xff\xd9" not in source_tail:
        raise JpegError("source has no EOI marker; use a complete original JPEG")
    donor_segments, _ = parse_header(donor, "donor")
    wanted = PROFILE_KINDS[profile]
    injected = collect_donor_segments(donor_segments, wanted)

    # Remove only metadata classes being replaced. Unrelated source metadata
    # and, by default, source EXIF remain intact.
    kept = [s for s in source_segments if metadata_kind(s) not in wanted]
    removed = [s for s in source_segments if metadata_kind(s) in wanted]
    insert_at = injection_index(kept)
    before = b"".join(s.raw for s in kept[:insert_at])
    after = b"".join(s.raw for s in kept[insert_at:])
    injected_raw = [s.raw for s in injected]
    initial = b"\xff\xd8" + before + b"".join(injected_raw) + after + source_tail

    advertised_second: int | None = None
    if "mpf" in wanted and mpf_offset_mode == "beyond-eof":
        cursor = 2 + len(before)
        for index, segment in enumerate(injected):
            if metadata_kind(segment) == "mpf":
                injected_raw[index], advertised_second = patch_mpf(
                    injected_raw[index], cursor, len(initial), missing_gap
                )
            cursor += len(injected_raw[index])

    output = b"\xff\xd8" + before + b"".join(injected_raw) + after + source_tail
    if len(output) != len(initial):
        raise AssertionError("MPF patch changed JPEG size")

    source_digest = coding_digest(source_segments, source_tail)
    output_segments, output_tail = parse_header(output, "output")
    output_digest = coding_digest(output_segments, output_tail)
    if source_digest != output_digest:
        raise AssertionError("source and output JPEG coding streams differ")

    details: BuildDetails = {
        "source_size": len(source),
        "output_size": len(output),
        "profile": profile,
        "removed": [kind for s in removed if (kind := metadata_kind(s)) is not None],
        "injected": [kind for s in injected if (kind := metadata_kind(s)) is not None],
        "coding_stream_sha256": source_digest,
        "advertised_second_image_offset": advertised_second,
    }
    return output, details


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="valid JPEG whose pixels are retained")
    parser.add_argument("output", type=Path, help="new malformed JPEG")
    parser.add_argument(
        "--donor",
        type=Path,
        default=Path(__file__).resolve().with_name("crash1.jpg"),
        help="metadata donor (default: crash1.jpg beside this script)",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILE_KINDS),
        default="all",
        help="donor metadata subset (default: all, for the closest reproduction)",
    )
    parser.add_argument(
        "--mpf-offset",
        choices=("beyond-eof", "donor"),
        default="beyond-eof",
        help="relocate the claimed gain map past EOF or retain donor values",
    )
    parser.add_argument(
        "--missing-gap",
        type=lambda value: int(value, 0),
        default=0x10000,
        help="distance past EOF for phantom gain map (default: 0x10000)",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.missing_gap < 1:
        parser.error("--missing-gap must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.output.exists() and not args.force:
        print(f"error: output exists (use --force): {args.output}", file=sys.stderr)
        return 2
    if args.source.resolve() == args.output.resolve():
        print("error: source and output must differ", file=sys.stderr)
        return 2
    try:
        output, details = build_output(
            args.source.read_bytes(),
            args.donor.read_bytes(),
            args.profile,
            args.mpf_offset,
            args.missing_gap,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(output)
    except (OSError, JpegError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"wrote: {args.output}")
    print(f"profile: {details['profile']}")
    print(f"source/output bytes: {details['source_size']}/{details['output_size']}")
    print("injected: " + ", ".join(details["injected"]))
    if details["removed"]:
        print("replaced source metadata: " + ", ".join(details["removed"]))
    print(f"JPEG coding-stream SHA-256: {details['coding_stream_sha256']}")
    advertised = details["advertised_second_image_offset"]
    if advertised is not None:
        print(f"phantom gain-map offset: {advertised} (EOF is {len(output)})")
    print("verified: source and output base-JPEG coding bytes are identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
