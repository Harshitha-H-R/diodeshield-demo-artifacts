from __future__ import annotations

import argparse


def main() -> None:
    argparse.ArgumentParser(description="Export versioned model artifacts").parse_args()
    print("No production model is exported by default.")


if __name__ == "__main__":
    main()
