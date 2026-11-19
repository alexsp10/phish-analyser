"""The VS Code extension package: manifest, contents, and the JSON contract it relies on."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from xml.etree import ElementTree

from conftest import DEMO_BRANDS, ROOT, SAMPLES

from phishcheck.cli import main

spec = importlib.util.spec_from_file_location("build_vsix", ROOT / "vscode-extension" / "build_vsix.py")
build_vsix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_vsix)


def test_vsix_contents(tmp_path):
    path = build_vsix.build(tmp_path / "x.vsix", python=None)
    with zipfile.ZipFile(path) as vsix:
        names = set(vsix.namelist())
        assert {
            "extension.vsixmanifest",
            "[Content_Types].xml",
            "extension/package.json",
            "extension/extension.js",
            "extension/media/ui.html",
        } <= names
        manifest = ElementTree.fromstring(vsix.read("extension.vsixmanifest"))
        identity = manifest.find(".//{http://schemas.microsoft.com/developer/vsx-schema/2011}Identity")
        package = json.loads(vsix.read("extension/package.json"))
        assert identity.get("Id") == package["name"] and identity.get("Version") == package["version"]
        assert package["contributes"]["configuration"]["properties"]["phishcheck.pythonPath"]["default"] == ""
        ui = vsix.read("extension/media/ui.html").decode()
        assert "<!--CSP-->" in ui and "acquireVsCodeApi" in ui


def test_python_path_is_only_baked_into_the_build(tmp_path):
    path = build_vsix.build(tmp_path / "x.vsix", python="C:/somewhere/python.exe")
    with zipfile.ZipFile(path) as vsix:
        package = json.loads(vsix.read("extension/package.json"))
    assert (
        package["contributes"]["configuration"]["properties"]["phishcheck.pythonPath"]["default"]
        == "C:/somewhere/python.exe"
    )
    source = json.loads((ROOT / "vscode-extension" / "package.json").read_text(encoding="utf-8"))
    assert source["contributes"]["configuration"]["properties"]["phishcheck.pythonPath"]["default"] == ""


def test_json_output_has_everything_the_panel_renders(capsys):
    main([str(SAMPLES / "phishing" / "01-lookalike-sender.eml"), "--json", "--brands", str(DEMO_BRANDS)])
    result = json.loads(capsys.readouterr().out)[0]
    for key in (
        "source",
        "subject",
        "from",
        "authentication",
        "verdict",
        "verdict_label",
        "score",
        "advice",
        "findings",
        "good_signs",
        "links",
        "attachments",
    ):
        assert key in result, key
    assert {"severity", "points", "title", "detail"} <= set(result["findings"][0])
