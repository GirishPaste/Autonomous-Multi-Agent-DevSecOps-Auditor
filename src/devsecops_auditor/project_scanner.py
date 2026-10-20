
"""Orchestrate the project's security scanners."""


"""Application entry point for project security scanning."""

from .scanners.project_scanner import scan_project

__all__ = ["scan_project"]
