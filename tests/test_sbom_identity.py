#!/usr/bin/env python3
"""SBOM identity uniqueness: the serialNumber (CycloneDX) and documentNamespace
(SPDX 2.3 §6.5) must be unique per build configuration, not just per
name+version, while an identical configuration still reproduces byte-for-byte.
Guards the config_identity fold in gen-sbom."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_SBOM = os.path.join(REPO, "share", "gen-sbom")

# gen-sbom has no .py extension, so load it by path with an explicit loader.
gs = SourceFileLoader("gen_sbom", GEN_SBOM).load_module()


class TestConfigIdentityUnit(unittest.TestCase):
    BASE = dict(lib_hash="a" * 64, license_id="GPL-2.0-only",
                build_props=[("HAVE_AES", "1")], enabled_deps=["wolfssl"],
                dep_versions={"wolfssl": "5.9.1"})

    def _id(self, **overrides):
        kw = dict(self.BASE, **overrides)
        return gs.config_identity(kw["lib_hash"], kw["license_id"],
                                  kw["build_props"], kw["enabled_deps"],
                                  kw["dep_versions"])

    def test_identical_inputs_reproduce(self):
        self.assertEqual(self._id(), self._id())

    def test_differs_on_build_props(self):
        self.assertNotEqual(
            self._id(),
            self._id(build_props=[("HAVE_AES", "1"), ("HAVE_FIPS", "1")]))

    def test_differs_on_lib_hash(self):
        self.assertNotEqual(self._id(), self._id(lib_hash="b" * 64))

    def test_differs_on_deps_and_versions(self):
        self.assertNotEqual(self._id(), self._id(enabled_deps=[]))
        self.assertNotEqual(self._id(),
                            self._id(dep_versions={"wolfssl": "5.9.2"}))

    def test_differs_on_license(self):
        self.assertNotEqual(self._id(),
                            self._id(license_id="LicenseRef-wolfSSL-Commercial"))

    def test_build_prop_order_independent(self):
        # build_props is sorted inside config_identity.
        self.assertEqual(
            self._id(build_props=[("A", "1"), ("B", "2")]),
            self._id(build_props=[("B", "2"), ("A", "1")]))


class TestSerialUniquenessEndToEnd(unittest.TestCase):
    @staticmethod
    def _write(path, data, mode="w"):
        with open(path, mode) as f:
            f.write(data)

    @staticmethod
    def _read_json(path):
        with open(path) as f:
            return json.load(f)

    def _run(self, d, opts_text, tag):
        oh = os.path.join(d, f"o-{tag}.h")
        self._write(oh, opts_text)
        lib = os.path.join(d, "lib.a")
        self._write(lib, b"!<arch>\n" + b"\0" * 32, "wb")
        lic = os.path.join(d, "LICENSE")
        self._write(lic, "GPL-2.0-only\n")
        cdx = os.path.join(d, f"{tag}.cdx.json")
        spdx = os.path.join(d, f"{tag}.spdx.json")
        r = subprocess.run(
            [sys.executable, GEN_SBOM, "--name", "wolfssl", "--version",
             "5.9.1", "--options-h", oh, "--lib", lib, "--license-file", lic,
             "--cdx-out", cdx, "--spdx-out", spdx],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return (self._read_json(cdx)["serialNumber"],
                self._read_json(spdx)["documentNamespace"])

    def test_different_config_distinct_same_config_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            nonfips = self._run(d, "#define HAVE_AES 1\n", "nonfips")
            fips = self._run(d, "#define HAVE_AES 1\n#define HAVE_FIPS 1\n",
                             "fips")
            again = self._run(d, "#define HAVE_AES 1\n", "again")
            self.assertNotEqual(nonfips[0], fips[0], "serialNumber collided")
            self.assertNotEqual(nonfips[1], fips[1],
                                "documentNamespace collided")
            self.assertEqual(nonfips, again, "same config not reproducible")


if __name__ == "__main__":
    unittest.main(verbosity=2)
