"""Keyring helpers for CertiNext credential resolution.

Provides lightweight wrappers around the optional ``keyring`` package.
All functions silently degrade when keyring is not installed rather than
raising an ImportError, so callers do not need to guard the import.
"""


def keyring_service(base: str, profile: str | None) -> str:
    """Return the keyring service name for a given base and optional profile.

    Args:
        base: Base service name (e.g. ``'certinext'``).
        profile: Profile suffix, or None for the default profile.

    Returns:
        ``'base-profile'`` when profile is set, otherwise ``'base'``.
    """
    return f"{base}-{profile}" if profile else base


def keyring_get(service: str, key: str) -> str | None:
    """Return a stored keyring value, or None if keyring is unavailable or unset.

    Args:
        service: Keyring service name.
        key: Keyring key (username field).

    Returns:
        The stored string, or None on any failure.
    """
    try:
        import keyring
        value = keyring.get_password(service, key)
        return value if isinstance(value, str) else None
    except Exception:
        return None
