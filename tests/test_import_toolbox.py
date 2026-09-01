from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from tools import import_toolbox as module


class ToolboxImportTests(unittest.TestCase):
    def create_archive(self, path: Path) -> None:
        scripts_buffer = BytesIO()
        with ZipFile(scripts_buffer, "w") as scripts:
            for name in module.ALLOWLIST:
                scripts.writestr(name, f"fixture:{name}\n")
        install_buffer = BytesIO()
        with ZipFile(install_buffer, "w") as install:
            install.writestr("STEP_1_UPLOAD_PACK/scripts.zip", scripts_buffer.getvalue())
        with ZipFile(path, "w") as outer:
            outer.writestr("INSTALL_KIT.zip", install_buffer.getvalue())

    def test_import_and_verify_allowlisted_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "lucy.zip"
            destination = root / "toolbox"
            self.create_archive(source)
            manifest = module.import_toolbox(source, destination)
            self.assertEqual(len(module.ALLOWLIST), manifest["asset_count"])
            self.assertEqual([], module.verify_toolbox(destination))
            (destination / module.ALLOWLIST[0]).write_text("tampered\n")
            self.assertTrue(any("hash mismatch" in error for error in module.verify_toolbox(destination)))


if __name__ == "__main__":
    unittest.main()