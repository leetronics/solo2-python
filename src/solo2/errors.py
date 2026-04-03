"""Error types for the Solo 2 core library."""

from __future__ import annotations


class Solo2Error(Exception):
    """Base error for Solo 2 core operations."""


class Solo2NotFoundError(Solo2Error):
    """Raised when no suitable Solo 2 device is available."""


class Solo2TransportError(Solo2Error):
    """Raised when a transport call fails."""


class Solo2CommandError(Solo2Error):
    """Raised when a device command fails with a logical protocol error."""


class Solo2PinRequiredError(Solo2CommandError):
    """Raised when an operation requires a PIN."""


class Solo2TouchRequiredError(Solo2CommandError):
    """Raised when an operation requires user touch."""


class Solo2WrongPinError(Solo2CommandError):
    """Raised when a PIN is wrong."""

    def __init__(self, message: str, attempts_remaining: int | None = None):
        super().__init__(message)
        self.attempts_remaining = attempts_remaining


class Solo2ConfirmationRequiredError(Solo2CommandError):
    """Raised when a destructive CLI action requires confirmation."""
