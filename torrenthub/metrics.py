"""Tiny Prometheus text-format metrics. No dependency, counters plus scrape-time gauges."""

from __future__ import annotations


class Metrics:
    def __init__(self) -> None:
        self._c: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def inc(self, name: str, value: float = 1, **labels: str) -> None:
        key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
        self._c[key] = self._c.get(key, 0) + value

    def get(self, name: str, **labels: str) -> float:
        return self._c.get((name, tuple(sorted((k, str(v)) for k, v in labels.items()))), 0)

    @staticmethod
    def _fmt(v: float) -> str:
        return str(int(v)) if float(v).is_integer() else repr(v)

    @staticmethod
    def _labels(labels: tuple[tuple[str, str], ...]) -> str:
        if not labels:
            return ""
        return "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"

    def render(self, gauges: dict[str, float] | None = None) -> str:
        lines: list[str] = []
        seen: set[str] = set()
        for (name, labels), value in sorted(self._c.items()):
            if name not in seen:
                lines.append(f"# TYPE {name} counter")
                seen.add(name)
            lines.append(f"{name}{self._labels(labels)} {self._fmt(value)}")
        for name, value in sorted((gauges or {}).items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {self._fmt(value)}")
        return "\n".join(lines) + "\n"
