# PyInstaller spec: one folder holding `torrenthub` and `git-remote-thub` that share their libraries.
#   pyinstaller --noconfirm --distpath dist-bin --workpath build-bin packaging/torrenthub.spec
# Build it from an environment that has the extras installed:  pip install '.[all]'
import os

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

HERE = SPECPATH  # this file's folder; the repository is one up
datas, binaries, hidden = [], [], []
# mcp.cli exits at import unless typer is installed, and nothing here uses it
hidden += collect_submodules("mcp", filter=lambda n: ".cli" not in n)
datas += collect_data_files("mcp")
for pkg in ("libtorrent", "coincurve", "websockets", "uvicorn", "certifi"):
    try:
        d, b, h = collect_all(pkg)
    except Exception:
        continue
    datas += d; binaries += b; hidden += h
hidden += collect_submodules("torrenthub") + collect_submodules("uvicorn") + ["h11", "anyio._backends._asyncio"]

def analysis(script):
    return Analysis([os.path.join(HERE, script)], pathex=[os.path.dirname(HERE)], binaries=binaries, datas=datas, hiddenimports=hidden,
                    excludes=["tkinter", "pytest", "numpy", "huggingface_hub"], noarchive=False)

a1, a2 = analysis("torrenthub_main.py"), analysis("git_remote_thub_main.py")
MERGE((a1, "torrenthub", "torrenthub"), (a2, "git-remote-thub", "git-remote-thub"))
p1, p2 = PYZ(a1.pure), PYZ(a2.pure)
e1 = EXE(p1, a1.scripts, [], exclude_binaries=True, name="torrenthub", console=True)
e2 = EXE(p2, a2.scripts, [], exclude_binaries=True, name="git-remote-thub", console=True)
coll = COLLECT(e1, a1.binaries, a1.datas, e2, a2.binaries, a2.datas, name="torrenthub")
