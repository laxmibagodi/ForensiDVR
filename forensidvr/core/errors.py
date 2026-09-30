"""Exception hierarchy. Every ForensiDVR error derives from :class:`ForensiDVRError`."""

from __future__ import annotations


class ForensiDVRError(Exception):
    """Base class for all ForensiDVR errors."""


class WriteBlockedError(ForensiDVRError, PermissionError):
    """Raised when code attempts to modify a write-protected evidence source."""


class CustodyLogError(ForensiDVRError):
    """Raised for chain-of-custody log failures."""


class CustodyLogTamperedError(CustodyLogError):
    """Raised when the custody log hash chain fails verification."""


class EvidenceIntegrityError(ForensiDVRError):
    """Raised when an evidence source no longer matches its acquisition hash."""


class ImageFormatError(ForensiDVRError):
    """Raised when an image container cannot be parsed."""


class CaseError(ForensiDVRError):
    """Raised for case database / case directory problems."""


class AcquisitionError(ForensiDVRError):
    """Raised when an acquisition cannot be started or completed."""
