#!/usr/bin/env python3
"""Install dependencies and extract a supported Sims 2, Urbz or Spyro Shadow Legacy DS dump."""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def extract(rom_path):
    import ndspy.codeCompression
    import ndspy.rom
    from stockersound import profile_for

    rom = rom_path.read_bytes()
    if len(rom) < 0x30:
        raise ValueError("File is too short to be a Nintendo DS ROM")
    offset, entry, base, size = struct.unpack_from("<4I", rom, 0x20)
    if (base, entry) != (0x02000000, 0x02000800) or offset + size > len(rom):
        raise ValueError("Unsupported ARM9 layout")
    footer = rom[offset + size : offset + size + 12]
    if footer[:4] == bytes.fromhex("2106c0de"):
        size += 12
    code = ndspy.codeCompression.decompress(rom[offset : offset + size])
    profile = profile_for(code)
    bank = ndspy.rom.NintendoDSRom(rom).getFileByName("SoundData.rom")
    if hashlib.sha256(bank).hexdigest() != profile.bank_sha256:
        raise ValueError("Unsupported SoundData bank")
    output = ROOT / "data"
    output.mkdir(parents=True, exist_ok=True)
    (output / "arm9.bin").write_bytes(code)
    (output / "SoundData.rom").write_bytes(bank)
    print(
        f"{profile.name}: extracted ARM9 ({len(code)} bytes) and SoundData ({len(bank)} bytes) to {output}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "rom", type=Path, help="Your supported Nintendo DS cartridge dump"
    )
    parser.add_argument("--extract-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    rom_path = args.rom.resolve()
    if not rom_path.is_file():
        parser.error(f"ROM not found: {rom_path}")
    try:
        if args.extract_only:
            extract(rom_path)
            return
        environment = ROOT / ".venv"
        python = environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        if not python.is_file():
            print("Creating local Python environment...", flush=True)
            venv.EnvBuilder(with_pip=True).create(environment)
        print("Installing ndspy and Unicorn...", flush=True)
        subprocess.run(
            [str(python), "-m", "pip", "install", "ndspy==4.2.0", "unicorn==2.1.4"],
            check=True,
        )
        subprocess.run(
            [
                str(python),
                str(Path(__file__).resolve()),
                str(rom_path),
                "--extract-only",
            ],
            check=True,
        )
        print("Ready. See README.md for export and native rendering commands.")
    except (ValueError, OSError, ImportError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Setup failed: {exc}\n")


if __name__ == "__main__":
    main()
