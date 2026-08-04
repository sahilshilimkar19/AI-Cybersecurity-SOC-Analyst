"""Errors raised by the tools layer.

These are *configuration* errors — a tool that does not exist, or an agent
reaching outside its allow-list. Operational failures (a record that will not
parse) are returned as typed :class:`~tools.base.ToolFailure` values instead, so
ordinary bad input never surfaces as an exception.
"""

from __future__ import annotations


class ToolError(Exception):
    """Base error for the tools layer."""


class ToolNotRegisteredError(ToolError):
    """A tool was requested that is not registered."""


class ToolNotPermittedError(ToolError):
    """An agent tried to invoke a tool outside its allow-list (least privilege)."""
