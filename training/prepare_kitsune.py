from __future__ import annotations

import argparse


def main() -> None:
    argparse.ArgumentParser(description="Prepare independent KitNET-compatible feature streams").parse_args()
    print("Use KitsuneAdapter warm-up/inference; original Kitsune licensing is not bundled.")


if __name__ == "__main__":
    main()
