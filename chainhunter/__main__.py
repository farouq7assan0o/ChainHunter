from .cli import main

# guard: on Windows, worker processes (hunt --lake --workers N) re-import this module; without the guard
# every worker would re-run the whole CLI
if __name__ == "__main__":
    raise SystemExit(main())
