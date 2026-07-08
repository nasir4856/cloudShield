import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_startup_script_exists_and_is_importable():
    spec = importlib.util.spec_from_file_location("failsafe_start", ROOT / "failsafe_start.py")
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert module is not None

    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)

    assert hasattr(module, "ensure_environment")
    assert hasattr(module, "main")
