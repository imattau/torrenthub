"""Entry point for the standalone build (PyInstaller): `torrenthub`."""
import sys

from torrenthub.cli import main

if __name__ == "__main__":
    sys.exit(main())
