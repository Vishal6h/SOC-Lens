"""Deterministic, offline evidence ingestion for SOCLens."""

from .builder import assemble_imports
from .service import ImportService

__all__ = ("ImportService", "assemble_imports")
