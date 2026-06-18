from importlib import metadata
from pathlib import Path


def main() -> None:
    dist = metadata.distribution("volatility3")
    license_dir = Path("/licenses/volatility3")
    license_dir.mkdir(parents=True, exist_ok=True)
    (license_dir / "METADATA").write_text(dist.read_text("METADATA") or "", encoding="utf-8")

    license_text = None
    for file_info in dist.files or []:
        name = str(file_info).lower()
        if name.endswith("license") or name.endswith("license.txt") or "license" in Path(name).name:
            try:
                license_text = Path(dist.locate_file(file_info)).read_text(encoding="utf-8")
            except Exception:
                license_text = None
            if license_text:
                break
    if not license_text:
        license_text = (
            "Volatility license text was not exposed by package metadata. "
            "See METADATA and https://www.volatilityfoundation.org/license/vsl-v1.0\n"
        )
    (license_dir / "LICENSE").write_text(license_text, encoding="utf-8")


if __name__ == "__main__":
    main()
