from pathlib import Path
from threading import RLock


class BlocklistService:
    """File-backed blocklist preserving the original project behavior."""

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self._lock = RLock()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_path.touch(exist_ok=True)
        self.blocked_ips: set[str] = self.load()

    def load(self) -> set[str]:
        with self._lock:
            return {
                line.strip()
                for line in self.file_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }

    def save(self) -> None:
        with self._lock:
            content = "".join(f"{ip}\n" for ip in sorted(self.blocked_ips))
            self.file_path.write_text(content, encoding="utf-8")

    def add(self, ip_address: str) -> None:
        with self._lock:
            self.blocked_ips.add(ip_address)
            self.save()

    def discard(self, ip_address: str) -> None:
        with self._lock:
            self.blocked_ips.discard(ip_address)
            self.save()

    def contains(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips

    def all(self) -> set[str]:
        return set(self.blocked_ips)

