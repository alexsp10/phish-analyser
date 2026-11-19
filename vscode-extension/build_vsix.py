"""Package the PhishCheck VS Code extension as a .vsix, using only the Python standard library.

A .vsix is a zip with a small manifest. Building it here means no Node.js / vsce is needed.

    python vscode-extension/build_vsix.py
    code --install-extension dist/phishcheck-0.1.0.vsix

By default the built extension is pointed at this project's .venv Python, so the
buttons work whichever folder you have open in VS Code. That absolute path is only
written into the built .vsix (which is git-ignored), never into the repository.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

CONTENT_TYPES = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".html" ContentType="text/html"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".txt" ContentType="text/plain"/>
</Types>
"""


def manifest(package: dict) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{escape(package["name"])}" Version="{escape(package["version"])}" Publisher="{escape(package["publisher"])}" />
    <DisplayName>{escape(package["displayName"])}</DisplayName>
    <Description xml:space="preserve">{escape(package["description"])}</Description>
    <Tags>{escape(",".join(package.get("keywords", [])))}</Tags>
    <Categories>{escape(",".join(package.get("categories", [])))}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="{escape(package["engines"]["vscode"])}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
    </Properties>
    <License>extension/LICENSE.txt</License>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE.txt" Addressable="true" />
  </Assets>
</PackageManifest>
"""


def build(output: Path, python: str | None) -> Path:
    package = json.loads((HERE / "package.json").read_text(encoding="utf-8"))
    if python:
        package["contributes"]["configuration"]["properties"]["phishcheck.pythonPath"]["default"] = python

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as vsix:
        vsix.writestr("[Content_Types].xml", CONTENT_TYPES)
        vsix.writestr("extension.vsixmanifest", manifest(package))
        vsix.writestr("extension/package.json", json.dumps(package, indent=2))
        vsix.write(HERE / "extension.js", "extension/extension.js")
        vsix.write(HERE / "README.md", "extension/README.md")
        vsix.write(ROOT / "LICENSE", "extension/LICENSE.txt")
        # The panel uses the exact same page as `phishcheck --gui`.
        vsix.write(ROOT / "src" / "phishcheck" / "ui.html", "extension/media/ui.html")
    return output


def main() -> None:
    venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
    if not venv_python.exists():
        venv_python = ROOT / ".venv" / "bin" / "python"
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "phishcheck-0.1.0.vsix")
    parser.add_argument(
        "--python",
        default=str(venv_python) if venv_python.exists() else None,
        help="default Python for the extension (default: this project's .venv)",
    )
    parser.add_argument("--no-python", action="store_true", help="don't set a default Python path")
    args = parser.parse_args()
    path = build(args.output, None if args.no_python else args.python)
    print(f"Built {path}")
    print(f'Install it with:  code --install-extension "{path}"')


if __name__ == "__main__":
    main()
