"""core/interfaces.py — Abstract base classes for all major components.

Import THESE in application code, never concrete implementations directly.
This keeps the dependency graph clean and check/reporter implementations swappable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from core.models import Finding, ScanResult, ScanType


class Check(ABC):
    """A single atomic security check.

    Subclasses MUST:
    - Set class attributes: check_id, scan_type, description
    - Only use HEAD/GET (or POST for AI probes with explicit user consent)
    - Return an empty list rather than raise on network errors (log instead)
    - Respect config["timeout"] and config.get("max_requests", 50)
    """

    check_id: str = ""
    scan_type: ScanType = ScanType.WEBSITE
    description: str = ""

    @abstractmethod
    async def run(self, target_url: str, session, config: dict) -> list[Finding]:
        ...


class Scanner(ABC):
    """Aggregates Check instances and runs a full scan."""

    @abstractmethod
    async def scan(self, target_url: str, config: dict) -> ScanResult:
        ...

    @abstractmethod
    def checks(self) -> list[Check]:
        """Return the registered Check instances (for UI introspection)."""
        ...


class Reporter(ABC):
    """Transforms a ScanResult into a serialised output artifact (bytes)."""

    @abstractmethod
    def render(self, result: ScanResult) -> bytes:
        ...


class Visualizer(ABC):
    """Prepares structured data consumed by the NiceGUI weak-points map."""

    @abstractmethod
    def build_graph(self, result: ScanResult) -> dict:
        """Return a graph dictionary consumed by the front-end components."""
        ...
