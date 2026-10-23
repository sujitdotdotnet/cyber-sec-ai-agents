import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Tests run without network or API keys: force rule-based mode and a throwaway vector store.
os.environ["SECAGENTS_OFFLINE"] = "1"
os.environ["CHROMA_DIR"] = tempfile.mkdtemp(prefix="secagents-test-chroma-")
atexit.register(shutil.rmtree, os.environ["CHROMA_DIR"], ignore_errors=True)  # do not leave a vector store behind per run
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
