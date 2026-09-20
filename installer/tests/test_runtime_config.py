"""Host-only checks of runtime config loading, stopping before router operations."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SH = sys.argv.pop(1) if len(sys.argv) > 1 else "sh"
if Path(SH).is_absolute():
    os.environ["PATH"] = str(Path(SH).parent) + os.pathsep + os.environ.get("PATH", "")
SOURCE = (ROOT / "hotswapper-main.sh").read_text(encoding="utf-8")
STARTUP = SOURCE[:SOURCE.index('PROFILE_FILE=')]
CONFIG = (ROOT / "config/hotswapper.conf").read_text(encoding="utf-8")
CONFIG = CONFIG.replace("TUNNEL_ID=''", "TUNNEL_ID='42'").replace("GROUP_ID=''", "GROUP_ID='7'")


class RuntimeConfigTests(unittest.TestCase):
    def load(self, config):
        with tempfile.TemporaryDirectory(prefix="hotswapper-config-") as directory:
            path = Path(directory) / "runtime.conf"
            if config is not None:
                path.write_text(config, encoding="utf-8", newline="\n")
            script = STARTUP.replace("/root/hotswapper/hotswapper.conf", path.as_posix())
            return subprocess.run([SH, "-c", script], capture_output=True, timeout=10).returncode

    def test_canonical_config_loads(self):
        self.assertEqual(0, self.load(CONFIG))

    def test_missing_or_invalid_config_blocks(self):
        for config in (None, "", CONFIG + "\n'broken"):
            with self.subTest(config=config is None):
                self.assertNotEqual(0, self.load(config))

    def test_numeric_settings_are_checked(self):
        for value in ("", "-1", "word", "08", "999999999999", "0"):
            with self.subTest(value=value):
                self.assertNotEqual(0, self.load(CONFIG.replace("DETECTOR_PERIOD_MS=400", "DETECTOR_PERIOD_MS=" + value)))
        self.assertNotEqual(0, self.load(CONFIG.replace("DEBUG_TIMING=0", "DEBUG_TIMING=2")))
        self.assertNotEqual(0, self.load(CONFIG.replace("READY_MAX_AGE_MS=5000\n", "")))


if __name__ == "__main__":
    unittest.main()
