from __future__ import annotations

import argparse


def main() -> None:
    argparse.ArgumentParser(description="Evaluate recorded labels and scores").parse_args()
    print("Evaluation scaffold: reports must be generated from measured labelled data.")


if __name__ == "__main__":
    main()
