from __future__ import annotations

import argparse


def main() -> None:
    argparse.ArgumentParser(description="Calibration experiment entry point").parse_args()
    print("Calibration is experimental; confidence is not a probability.")


if __name__ == "__main__":
    main()
