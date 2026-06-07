"""Application entry point for Gleipnir IDS."""

from src.cli import main as cli_main


def main() -> int:
    """Run the command line interface."""
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
