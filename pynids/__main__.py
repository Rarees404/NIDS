"""Allow ``python -m pynids`` (used by the launchd daemon)."""
from .cli import main

if __name__ == "__main__":
    main()
