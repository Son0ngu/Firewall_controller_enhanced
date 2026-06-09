from pathlib import Path
import os
import shutil
import subprocess
import sys
import zlib
import urllib.request


PLANTUML_SERVER = "https://www.plantuml.com/plantuml"


def _find_jar() -> Path | None:
    """Locate a local plantuml.jar.

    Order: $PLANTUML_JAR, then plantuml.jar next to this script, then in CWD.
    Local rendering avoids the public server's GET-URL length limit (large
    diagrams with many notes return HTTP 400 over GET).
    """
    env_jar = os.environ.get("PLANTUML_JAR")
    candidates = []
    if env_jar:
        candidates.append(Path(env_jar))
    candidates.append(Path(__file__).resolve().parent / "plantuml.jar")
    candidates.append(Path("plantuml.jar"))
    for jar in candidates:
        if jar.exists():
            return jar
    return None


def render_with_jar(files, jar: Path, fmt: str = "svg") -> None:
    java = shutil.which("java")
    if not java:
        raise RuntimeError("java not found on PATH")
    cmd = [java, "-jar", str(jar), f"-t{fmt}", *[str(f) for f in files]]
    subprocess.run(cmd, check=True)
    for f in files:
        print(f"Rendered: {Path(f).with_suffix('.' + fmt)}")


def encode64(data: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

    def append3bytes(b1, b2, b3):
        c1 = b1 >> 2
        c2 = ((b1 & 0x3) << 4) | (b2 >> 4)
        c3 = ((b2 & 0xF) << 2) | (b3 >> 6)
        c4 = b3 & 0x3F
        return alphabet[c1] + alphabet[c2] + alphabet[c3] + alphabet[c4]

    result = ""
    i = 0

    while i < len(data):
        b1 = data[i]
        b2 = data[i + 1] if i + 1 < len(data) else 0
        b3 = data[i + 2] if i + 2 < len(data) else 0
        result += append3bytes(b1, b2, b3)
        i += 3

    return result


def plantuml_encode(text: str) -> str:
    compressed = zlib.compress(text.encode("utf-8"))[2:-4]
    return encode64(compressed)


def render_puml(input_path: Path, fmt: str = "svg") -> None:
    source = input_path.read_text(encoding="utf-8")
    encoded = plantuml_encode(source)

    url = f"{PLANTUML_SERVER}/{fmt}/{encoded}"
    output_path = input_path.with_suffix(f".{fmt}")

    request = urllib.request.Request(
    url,
    headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "image/svg+xml,image/png,*/*"
    }
)

    with urllib.request.urlopen(request, timeout=30) as response:
        output_path.write_bytes(response.read())

    print(f"Rendered: {output_path}")


def main():
    if len(sys.argv) > 1:
        files = [Path(arg) for arg in sys.argv[1:]]
    else:
        files = list(Path(".").glob("*.puml"))

    if not files:
        print("No .puml files found in current folder.")
        return

    existing = [f for f in files if f.exists()]
    for f in files:
        if not f.exists():
            print(f"Not found: {f}")

    # Prefer a local plantuml.jar (no URL-length limit); fall back to server.
    jar = _find_jar()
    if jar:
        print(f"Rendering locally via {jar}")
        render_with_jar(existing, jar, fmt="svg")
        return

    print("No local plantuml.jar found - using public server (may HTTP 400 on large diagrams).")
    for file in existing:
        render_puml(file, fmt="svg")


if __name__ == "__main__":
    main()