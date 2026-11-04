"""PyInstaller entry script: runs the package the way ``python -m`` does,
since a frozen app can't start from a module with relative imports."""

from pinginfoview.__main__ import main

raise SystemExit(main())
