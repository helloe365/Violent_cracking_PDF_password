class RecoveryError(Exception):
    """Base error shown to CLI users."""

    code = "recovery"


class ConfigurationError(RecoveryError, ValueError):
    code = "configuration"


class MaskSyntaxError(ConfigurationError):
    pass


class WordlistDecodeError(ConfigurationError):
    pass


class PlanSchemaError(ConfigurationError):
    code = "plan_schema"


class PdfValidationError(RecoveryError):
    pass


class CheckpointError(RecoveryError):
    pass


class SessionMismatch(CheckpointError):
    pass


class ActiveSession(RecoveryError):
    code = "active_session"


class BackendError(RecoveryError):
    pass


class CapabilityError(BackendError):
    code = "capability"


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
