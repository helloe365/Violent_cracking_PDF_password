"""Local PDF password recovery package."""

from .models import (
    BackendChoice,
    BruteAttack,
    DictionaryAttack,
    MaskAttack,
    RecoveryConfig,
)

__all__ = [
    "BackendChoice",
    "BruteAttack",
    "DictionaryAttack",
    "MaskAttack",
    "RecoveryConfig",
]

__version__ = "1.0.0"
