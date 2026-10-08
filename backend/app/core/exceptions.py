class PolyShieldException(Exception):
    """Base exception for PolyShield AI domain errors."""
    def __init__(self, message: str, error_code: str = "INTERNAL_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class ScanNotFoundException(PolyShieldException):
    """Raised when a requested scan_id does not exist."""
    def __init__(self, scan_id: str):
        super().__init__(
            message=f"Scan with ID '{scan_id}' not found.",
            error_code="SCAN_NOT_FOUND"
        )
        self.scan_id = scan_id


class InvalidStateTransitionException(PolyShieldException):
    """Raised when an illegal scan state transition is attempted."""
    def __init__(self, current_status: str, target_status: str):
        super().__init__(
            message=f"Cannot transition scan from '{current_status}' to '{target_status}'. Legal next state is required.",
            error_code="INVALID_STATE_TRANSITION"
        )
        self.current_status = current_status
        self.target_status = target_status


class InvalidPEFileException(PolyShieldException):
    """Raised when an uploaded binary is not a valid Windows PE file."""
    def __init__(self, detail: str = "Invalid or corrupted Windows Portable Executable (PE) format."):
        super().__init__(
            message=detail,
            error_code="INVALID_PE_FILE"
        )


class FileTooLargeException(PolyShieldException):
    """Raised when an uploaded binary exceeds configured size limits."""
    def __init__(self, size_bytes: int, max_bytes: int):
        super().__init__(
            message=f"Uploaded file size ({size_bytes} bytes) exceeds maximum limit ({max_bytes} bytes).",
            error_code="FILE_TOO_LARGE"
        )


class EmptyFileException(PolyShieldException):
    """Raised when an uploaded binary file is 0 bytes."""
    def __init__(self):
        super().__init__(
            message="Uploaded file is empty (0 bytes).",
            error_code="EMPTY_FILE"
        )


class PathTraversalException(PolyShieldException, ValueError):
    """Raised when a path traversal attempt is detected."""
    def __init__(self, path: str):
        super().__init__(
            message=f"Invalid or unsafe storage reference: path traversal blocked for candidate path '{path}'. File path escapes allowed root directory.",
            error_code="PATH_TRAVERSAL_BLOCKED"
        )


class ModelIntegrityException(PolyShieldException):
    """Raised when model artifact SHA-256 verification fails."""
    def __init__(self, detail: str):
        super().__init__(
            message=f"Model integrity verification failed: {detail}",
            error_code="MODEL_INTEGRITY_FAILURE"
        )


class AuthenticationException(PolyShieldException):
    """Raised when authentication credentials or tokens are invalid/missing."""
    def __init__(self, detail: str = "Authentication credentials required."):
        super().__init__(
            message=detail,
            error_code="AUTHENTICATION_REQUIRED"
        )


class AuthorizationException(PolyShieldException):
    """Raised when authenticated user lacks permissions for an operation."""
    def __init__(self, detail: str = "Access denied. Insufficient permissions."):
        super().__init__(
            message=detail,
            error_code="AUTHORIZATION_DENIED"
        )


class StaticAnalysisFailedException(PolyShieldException):
    """Raised when static analysis processing fails."""
    def __init__(self, detail: str):
        super().__init__(
            message=f"Static analysis failed: {detail}",
            error_code="STATIC_ANALYSIS_FAILED"
        )


class ModelServiceUnavailableException(PolyShieldException):
    """Raised when the ML model artifact is unavailable or unreadable."""
    def __init__(self, detail: str = "Static ML model is unavailable."):
        super().__init__(
            message=f"ML Model service unavailable: {detail}",
            error_code="MODEL_SERVICE_UNAVAILABLE"
        )


class ModelContractValidationException(PolyShieldException):
    """Raised when model metadata or feature contract validation fails."""
    def __init__(self, detail: str):
        super().__init__(
            message=f"Model contract validation failed: {detail}",
            error_code="MODEL_CONTRACT_VALIDATION_FAILED"
        )
