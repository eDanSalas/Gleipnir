
from src.cli import main as cli_main


# FUN-083
def main() -> int:
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
