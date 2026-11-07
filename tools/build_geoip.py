#!/usr/bin/env python3
"""Convert DB-IP "IP to Country Lite" IPv4 CSV into the compact binary used by the app.

Input:  dbip-country-ipv4-num.csv  (start,end,CC) from npm @ip-location-db/dbip-country
Output: geoip-v4.bin

Format (big endian):
  "GEO4" | u32 count | u32 version (yyyymmddhh from package version)
  count * u32 range start (sorted)
  count * 2 bytes ISO country code, "--" = unknown / not allocated
Lookup = binary search for the last start <= ip.
"""
import struct
import sys


def main(src: str, dst: str, version: int) -> None:
    starts, codes = [], []
    expected = 0
    with open(src, encoding="ascii") as fh:
        for line in fh:
            a, b, cc = line.strip().split(",")
            a, b = int(a), int(b)
            cc = (cc.upper() + "--")[:2] if cc else "--"
            if a > expected:  # hole in the data
                if not codes or codes[-1] != "--":
                    starts.append(expected)
                    codes.append("--")
            if not codes or codes[-1] != cc:
                starts.append(a)
                codes.append(cc)
            expected = b + 1
    if expected <= 0xFFFFFFFF and (not codes or codes[-1] != "--"):
        starts.append(expected)
        codes.append("--")
    if starts[0] != 0:
        starts.insert(0, 0)
        codes.insert(0, "--")
    with open(dst, "wb") as out:
        out.write(b"GEO4")
        out.write(struct.pack(">II", len(starts), version))
        out.write(struct.pack(">%dI" % len(starts), *starts))
        out.write("".join(codes).encode("ascii"))
    print(f"{len(starts)} ranges -> {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: build_geoip.py <dbip-country-ipv4-num.csv> <out.bin> <version>")
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
