import sys
from pathlib import Path

# Ensure the repo root is importable so `import app.*` works from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))
