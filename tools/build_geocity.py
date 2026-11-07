#!/usr/bin/env python3
"""Convert DB-IP "IP to City Lite" IPv4 CSV into the compact city asset used by the app.

Input:  dbip-city-ipv4-num.csv  (start,end,cc,region,region2,city,postcode,lat,lon,tz)
        from npm @ip-location-db/dbip-city-7z
Output: geocity-v4.bin

Only cities with a lot of address space (where data centres are) keep their own name;
small towns are merged into their region, marked with a trailing "*". This keeps the file
small while Moscow, St Petersburg, Tashkent, Almaty, Jakarta, ... stay separate.

Format (big endian):
  "CTY1" | u32 count | u32 version | u32 nameCount | u32 namesLen | names (UTF-8, "\n" separated, "CC|Name")
  count varint deltas of range starts (first delta is from 0)
  count * u16 name index
Name 0 is always "--|" (unknown).
"""
import collections
import re
import struct
import sys

MIN_CITY_ADDRESSES = 1 << 16
PAREN = re.compile(r"\s*\(.*\)\s*$")


def clean(name: str) -> str:
    return PAREN.sub("", name).strip()


def main(src: str, dst: str, version: int) -> None:
    rows = []
    size = collections.Counter()
    with open(src, encoding="utf-8") as fh:
        for line in fh:
            p = line.rstrip("\n").split(",")
            a, b, cc, region, city = int(p[0]), int(p[1]), p[2].upper(), clean(p[3]), clean(p[5])
            rows.append((a, b, cc, region, city))
            size[(cc, city)] += b - a + 1

    names = {"--|": 0}
    starts, ids = [], []

    def add(start: int, key: str) -> None:
        idx = names.setdefault(key, len(names))
        if not ids or ids[-1] != idx:
            starts.append(start)
            ids.append(idx)

    expected = 0
    for a, b, cc, region, city in rows:
        if a > expected:
            add(expected, "--|")
        if city and size[(cc, city)] >= MIN_CITY_ADDRESSES:
            key = f"{cc}|{city}"
        else:
            key = f"{cc}|{(region or city or '?')}*"
        add(a, key)
        expected = b + 1
    if expected <= 0xFFFFFFFF:
        add(expected, "--|")
    if starts[0] != 0:
        starts.insert(0, 0)
        ids.insert(0, 0)
    assert len(names) < 65536, len(names)

    blob = "\n".join(names.keys()).encode("utf-8")
    with open(dst, "wb") as out:
        out.write(b"CTY1")
        out.write(struct.pack(">IIII", len(starts), version, len(names), len(blob)))
        out.write(blob)
        prev = 0
        buf = bytearray()
        for s in starts:
            d = s - prev
            prev = s
            while d >= 0x80:
                buf.append((d & 0x7F) | 0x80)
                d >>= 7
            buf.append(d)
        out.write(buf)
        out.write(struct.pack(">%dH" % len(ids), *ids))
    print(f"{len(starts)} ranges, {len(names)} names -> {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: build_geocity.py <dbip-city-ipv4-num.csv> <out.bin> <version>")
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
