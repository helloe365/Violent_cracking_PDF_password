class RecoveryError(Exception):
    """Base error shown to CLI users."""


class ConfigurationError(RecoveryError, ValueError):
    pass


class MaskSyntaxError(ConfigurationError):
    pass


class WordlistDecodeError(ConfigurationError):
    pass


class PdfValidationError(RecoveryError):
    pass


class CheckpointError(RecoveryError):
    pass


class SessionMismatch(CheckpointError):
    pass


class BackendError(RecoveryError):
    pass


class ToolUnavailable(BackendError):
    pass


class ToolIncompatible(BackendError):
    pass


class HashExtractionError(BackendError):
    pass


class UnsupportedPdfHash(BackendError):
    pass


class HashcatExecutionError(BackendError):
    pass


class WorkerExecutionError(BackendError):
    pass
