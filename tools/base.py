"""Tool result types and the allow-listed tool registry (EDS §3.7).

Tools are the **deterministic** half of the system: parsing, extraction,
correlation, scoring. Keeping them out of the reasoning layer is what makes them
unit-testable and their behavior reproducible.

Two rules from the module spec are enforced here rather than left to discipline:

* **Typed failures, never swallowed exceptions.** A tool returns a result that is
  either a value or a named failure, so a caller cannot mistake "it broke" for
  "there was nothing".
* **Least privilege.** Each agent may invoke only its allow-listed tools; asking
  for anything else raises rather than silently succeeding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Generic, TypeVar

from tools.errors import ToolNotPermittedError, ToolNotRegisteredError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

T = TypeVar("T")


@dataclass(frozen=True)
class ToolFailure:
    """A named, inspectable tool failure."""

    tool: str
    reason: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.tool}: {self.reason}" + (f" ({self.detail})" if self.detail else "")


@dataclass(frozen=True)
class ToolResult(Generic[T]):
    """Either a value or a failure — never both, never neither."""

    value: T | None = None
    failure: ToolFailure | None = None

    @property
    def ok(self) -> bool:
        """Whether the tool produced a value."""
        return self.failure is None

    def unwrap(self) -> T:
        """Return the value, raising if this is a failure.

        Callers that can degrade should check :attr:`ok` instead.
        """
        if self.failure is not None or self.value is None:
            raise ValueError(f"tool result has no value: {self.failure}")
        return self.value

    @classmethod
    def succeed(cls, value: T) -> ToolResult[T]:
        return cls(value=value)

    @classmethod
    def fail(cls, tool: str, reason: str, detail: str = "") -> ToolResult[T]:
        return cls(failure=ToolFailure(tool=tool, reason=reason, detail=detail))


@dataclass(frozen=True)
class ToolSpec:
    """A registered tool: its name, what it does, and the callable behind it."""

    name: str
    description: str
    handler: Callable[..., object]


class ToolRegistry:
    """Registry of deterministic tools with per-agent allow-lists."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._allow_lists: dict[str, frozenset[str]] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register a tool, refusing duplicate names."""
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def grant(self, agent: str, tool_names: Iterable[str]) -> None:
        """Allow-list the tools an agent may invoke, validating each exists."""
        names = frozenset(tool_names)
        unknown = sorted(names - set(self._tools))
        if unknown:
            raise ToolNotRegisteredError(f"unknown tools for {agent!r}: {', '.join(unknown)}")
        self._allow_lists[agent] = names

    def allowed(self, agent: str) -> frozenset[str]:
        """The tools this agent may invoke (empty if none were granted)."""
        return self._allow_lists.get(agent, frozenset())

    def get(self, agent: str, name: str) -> ToolSpec:
        """Resolve a tool for an agent, enforcing the allow-list (deny by default)."""
        if name not in self._tools:
            raise ToolNotRegisteredError(f"unknown tool: {name}")
        if name not in self.allowed(agent):
            raise ToolNotPermittedError(f"agent {agent!r} may not invoke tool {name!r}")
        return self._tools[name]

    def names(self) -> list[str]:
        """Every registered tool name, sorted."""
        return sorted(self._tools)


@dataclass
class ToolCallLog:
    """Per-call record of tool usage (EDS §3.7 logging)."""

    calls: list[dict[str, object]] = field(default_factory=list)

    def record(self, *, tool: str, ok: bool, detail: str = "") -> None:
        self.calls.append({"tool": tool, "ok": ok, "detail": detail})

    def failures(self) -> list[dict[str, object]]:
        return [call for call in self.calls if not call["ok"]]
