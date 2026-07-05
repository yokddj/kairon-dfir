"""Allow running the CLI with python -m app.cli"""
from app.cli._commands import main

if __name__ == "__main__":
    main()
