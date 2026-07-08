import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def ensure_environment() -> None:
    """Create a basic .env file from the example when missing."""
    if ENV_FILE.exists():
        return

    if ENV_EXAMPLE.exists():
        ENV_FILE.write_text(ENV_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Created {ENV_FILE.name} from {ENV_EXAMPLE.name}.")
    else:
        ENV_FILE.write_text(
            "SECRET_KEY=replace-with-a-long-random-secret\n",
            encoding="utf-8",
        )
        print("Created a minimal .env file because no example file was found.")


def ensure_dependencies() -> None:
    """Install requirements if the environment is missing packages."""
    if shutil.which("pip") is None:
        return

    try:
        import flask  # noqa: F401
    except Exception:
        print("Installing Python dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])


def run_app() -> None:
    """Launch the Flask application with a clear fallback."""
    if not (ROOT / "app").exists():
        raise SystemExit("Application directory not found.")

    cmd = [sys.executable, "app.py"]
    print(f"Starting CloudShield with: {' '.join(cmd)}")
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> None:
    ensure_environment()
    ensure_dependencies()
    run_app()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Shut down requested.")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"Application exited with code {exc.returncode}") from exc
    except Exception as exc:
        raise SystemExit(f"Startup failed: {exc}") from exc
