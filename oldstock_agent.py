# oldstock_agent.py
# AI-style CTF solver agent for OldStock Router firmware

import pathlib
import re
import zlib
import sys


FLAG_PATTERN = re.compile(r"UCSI\d*\{[^}]+\}")


class OldStockAgent:
    def __init__(self, firmware_path):
        self.firmware_path = pathlib.Path(firmware_path)
        self.data = b""

    def say(self, message):
        print(f"[agent] {message}")

    def load_firmware(self):
        self.say(f"Loading firmware: {self.firmware_path}")

        if not self.firmware_path.exists():
            raise FileNotFoundError("Firmware file not found.")

        self.data = self.firmware_path.read_bytes()
        self.say(f"Firmware size: {len(self.data)} bytes")

    def show_basic_strings(self):
        self.say("Looking for readable text inside the firmware...")

        strings = re.findall(rb"[ -~]{4,}", self.data)

        for item in strings[:30]:
            print(item.decode("latin1", errors="replace"))

    def find_squashfs(self):
        self.say("Searching for SquashFS filesystem marker...")

        marker = b"hsqs"
        offset = self.data.find(marker)

        if offset == -1:
            self.say("SquashFS marker not found.")
            return None

        self.say(f"Found SquashFS marker at offset: 0x{offset:x}")
        return offset

    def try_zlib_extract(self):
        self.say("Trying to find gzip/zlib compressed content...")

        results = []

        for offset in range(len(self.data)):
            try:
                extracted = zlib.decompress(self.data[offset:])
                if len(extracted) > 20:
                    results.append((offset, extracted))
            except Exception:
                pass

        if not results:
            self.say("No zlib-compressed content found.")
            return []

        self.say(f"Found {len(results)} possible compressed block(s).")
        return results

    def inspect_extracted_blocks(self, blocks):
        for offset, extracted in blocks:
            self.say(f"Inspecting decompressed block from offset 0x{offset:x}")

            text = extracted.decode("latin1", errors="replace")
            print("\n===== Extracted Text =====")
            print(text)
            print("==========================\n")

            flags = FLAG_PATTERN.findall(text)

            if flags:
                self.say("Flag found!")
                for flag in flags:
                    print(f"FLAG: {flag}")
                return flags

        self.say("No flag found in extracted blocks.")
        return []

    def solve(self):
        self.say("Starting OldStock Router firmware investigation.")

        self.load_firmware()
        self.show_basic_strings()
        self.find_squashfs()

        blocks = self.try_zlib_extract()
        flags = self.inspect_extracted_blocks(blocks)

        if flags:
            self.say("Challenge solved.")
        else:
            self.say("Challenge not solved yet. Try manual firmware extraction next.")

        return flags


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python oldstock_agent.py OldStock_Router_FW_v1.2.3.bin")
        return

    agent = OldStockAgent(sys.argv[1])
    agent.solve()


if __name__ == "__main__":
    main()