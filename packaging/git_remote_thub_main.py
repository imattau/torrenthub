"""Entry point for the standalone build (PyInstaller): `git-remote-thub`, the helper git runs for thub:// URLs."""
import sys

from torrenthub.gitremote import main

if __name__ == "__main__":
    sys.exit(main())
