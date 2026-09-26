"""The staging boundary must copy bytes without following host filesystem links."""

import importlib.util
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

INFRA = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, INFRA / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load_script("stage-scenario")
extract = load_script("extract-scenario")


class ScenarioStreamTests(unittest.TestCase):
    def test_regular_files_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "source")
            source.mkdir()
            Path(source, "nested").mkdir()
            Path(source, "nested", "action.json").write_text('{"command":"echo ok"}')
            archive = io.BytesIO()
            stage.stage(source, archive)
            extract.DESTINATION = Path(root, "destination")
            extract.extract(io.BytesIO(archive.getvalue()))
            self.assertEqual(
                Path(root, "destination", "nested", "action.json").read_text(),
                '{"command":"echo ok"}',
            )

    def test_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "source")
            source.mkdir()
            outside = Path(root, "secret")
            outside.write_text("must not be copied")
            Path(source, "link").symlink_to(outside)
            with self.assertRaises(ValueError):
                stage.stage(source, io.BytesIO())
            Path(source, "link").unlink()
            os.link(outside, Path(source, "hardlink"))
            with self.assertRaises(ValueError):
                stage.stage(source, io.BytesIO())

    def test_archive_traversal_is_rejected(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as output:
            info = tarfile.TarInfo("../escape")
            info.size = 4
            output.addfile(info, io.BytesIO(b"oops"))
        with tempfile.TemporaryDirectory() as root:
            extract.DESTINATION = Path(root, "destination")
            with self.assertRaises(ValueError):
                extract.extract(io.BytesIO(archive.getvalue()))
            self.assertFalse(Path(root, "escape").exists())

    def test_file_limit_is_enforced_before_copy(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "source")
            source.mkdir()
            Path(source, "large").write_bytes(b"x" * 10)
            old_limit = stage.MAX_BYTES
            try:
                stage.MAX_BYTES = 9
                with self.assertRaises(ValueError):
                    stage.stage(source, io.BytesIO())
            finally:
                stage.MAX_BYTES = old_limit

    def test_entry_limit_includes_empty_directories(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "source")
            source.mkdir()
            for number in range(3):
                Path(source, f"empty-{number}").mkdir()
            old_limit = stage.MAX_ENTRIES
            try:
                stage.MAX_ENTRIES = 2
                with self.assertRaises(ValueError):
                    stage.stage(source, io.BytesIO())
            finally:
                stage.MAX_ENTRIES = old_limit


if __name__ == "__main__":
    unittest.main()
