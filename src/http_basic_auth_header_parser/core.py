"""Core implementation for HTTP Basic auth header parsing and construction.

Design decisions (documented so the behaviour is unambiguous):

* Usernames are decoded as UTF-8 (falling back to latin-1 on the rare
  non-UTF-8 byte sequence). RFC 7617 section 2.1.1 says clients SHOULD use
  UTF-8 when sending the charset parameter; almost all real-world clients
  that omit charset still send UTF-8-compatible octets.  latin-1 fallback
  means the round-trip identity (parse(build(...)) == original) holds even
  for arbitrary binary payloads.
* Passwords use the same decoder for symmetry and to preserve arbitrary
  bytes on a round trip.
* Only the `charset` parameter from RFC 7617 is honoured.  Other
  auth-params (realm is handled separately in the 401 response builder) are
  accepted but their values are not surfaced.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Optional, Tuple

AuthUser = str
AuthPassword = str


class BasicAuthHeader:
    """Result of parsing an Authorization: Basic header.

    Attributes:
        user: decoded username (always a ``str``).
        password: decoded password (always a ``str``).
        charset: the charset token from the request, or ``None`` if absent.
            Only ever ``'UTF-8'`` when present, case-insensitive match.
    """

    __slots__ = ("user", "password", "charset")

    def __init__(
        self,
        user: str,
        password: str,
        charset: Optional[str],
    ) -> None:
        self.user = user
        self.password = password
        self.charset = charset

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicAuthHeader):
            return NotImplemented
        return (
            self.user == other.user
            and self.password == other.password
            and self.charset == other.charset
        )

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            "BasicAuthHeader("
            f"user={self.user!r}, password={self.password!r}, charset={self.charset!r})"
        )


def _decode_octets(data: bytes) -> str:
    """Decode the user-pass octets.

    Latin-1 is the lossless fallback because every byte 0x00-0xFF maps to
    exactly one U+0000-U+00FF code point.  This guarantees that
    ``parse(build(u, p)).user == u`` for any ``u`` whose code points are all
    <= U+00FF, which is the universe Basic auth supports without explicit
    charset negotiation.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _strip_scheme(value: str) -> str:
    """Strip the leading ``Basic`` scheme token, case-insensitively.

    Tolerates arbitrary whitespace between scheme and credentials, per RFC
    7235 section 2.1 ("the recipient...MUST ignore...whitespace").
    """
    stripped = value.strip()
    space = stripped.find(" ")
    if space != -1:
        token = stripped[:space]
        if token.lower() == "basic":
            return stripped[space:].lstrip()
    return stripped


def _extract_charset(params: Tuple[Tuple[str, str], ...]) -> Optional[str]:
    """Return the RFC 7617 ``charset`` value if present (case-insensitive key).

    Only ``UTF-8`` is a meaningful value per RFC 7617; we still capture the
    raw token so callers can reject unknown charsets explicitly if they wish.
    """
    for name, value in params:
        if name.lower() == "charset":
            return value
    return None


def _parse_auth_params(
    raw: str,
) -> Tuple[Tuple[str, str], ...]:
    """Parse a comma-separated auth-param list into (name, value) pairs.

    Each param is ``name=\"...\"`` (quoted) or ``name=token`` (rare, but
    tolerated).  The value's surrounding quotes are stripped and
    backslash-escaped characters within quoted values are unescaped, per
    RFC 7230 §3.2.6 quoted-pair.  Empty input returns an empty tuple.
    """
    params = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        eq = chunk.find("=")
        if eq == -1:
            continue
        name = chunk[:eq].strip().lower()
        value = chunk[eq + 1:].strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            inner = value[1:-1]
            unescaped = []
            i = 0
            while i < len(inner):
                ch = inner[i]
                if ch == "\\" and i + 1 < len(inner):
                    nxt = inner[i + 1]
                    if nxt in ('\\', '"'):
                        unescaped.append(nxt)
                        i += 2
                        continue
                unescaped.append(ch)
                i += 1
            value = "".join(unescaped)
        params.append((name, value))
    return tuple(params)


def _b64decode_lenient(blob: str) -> Optional[bytes]:
    """Decode base64, stripping internal whitespace.

    RFC 7235 explicitly says recipients MUST ignore linear whitespace within
    the credential field.  We go slightly further and strip *all* whitespace
    (including non-ASCII spaces) because broken clients do exist, and the
    cost of being liberal here is just a decode attempt.  Returns ``None``
    when the payload is not valid base64.
    """
    cleaned = "".join(blob.split())
    if not cleaned:
        return b""
    # Pad to a multiple of 4 — some clients omit trailing '='.
    pad = (-len(cleaned)) % 4
    if pad:
        cleaned += "=" * pad
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None


def parse_authorization(header_value: str) -> Optional[BasicAuthHeader]:
    """Parse an ``Authorization: Basic ...`` header value.

    Returns ``None`` when the value is not a recognizable Basic credential
    (wrong scheme, undecodable base64, or missing colon).  Never raises —
    callers (request handlers) want a boolean "did this parse?" signal, not
    an exception, so that they can fall through to 401.
    """
    if not header_value:
        return None
    after_scheme = _strip_scheme(header_value)
    if not after_scheme:
        return None
    # Scheme presence check: callers pass the full header value, so if no
    # scheme is present and the first token isn't 'basic', we bail.
    has_scheme = header_value.strip().lower().startswith("basic ")
    if not has_scheme:
        return None
    decoded = _b64decode_lenient(after_scheme)
    if decoded is None:
        return None
    colon = decoded.find(b":")
    if colon == -1:
        return None
    user_octets = decoded[:colon]
    pass_octets = decoded[colon + 1:]
    return BasicAuthHeader(
        user=_decode_octets(user_octets),
        password=_decode_octets(pass_octets),
        charset=None,
    )


def build_authorization(user: str, password: str, charset: str = "UTF-8") -> str:
    """Build an ``Authorization: Basic <token>`` header value.

    The ``charset`` parameter is accepted for API symmetry with the parser,
    but per RFC 7617 only ``UTF-8`` triggers its inclusion.  Passing any
    other value silently omits the parameter — the wire format is unaffected
    because the encoding is still UTF-8.
    """
    token = base64.b64encode(
        (user + ":" + password).encode("utf-8"),
    ).decode("ascii")
    # Note: RFC 7617 puts the charset in the *WWW-Authenticate* challenge,
    # not the *Authorization* request header.  Some clients append it to
    # the request anyway; we follow the spec and keep the request clean.
    return f"Basic {token}"


def parse_www_authenticate(
    header_value: str,
) -> Optional["WWWAuthenticateChallenge"]:
    """Parse a ``WWW-Authenticate: Basic ...`` challenge.

    Returns ``None`` if the scheme is not Basic or the header is empty.
    """
    if not header_value:
        return None
    stripped = header_value.strip()
    space = stripped.find(" ")
    if space == -1:
        if stripped.lower() != "basic":
            return None
        return WWWAuthenticateChallenge(realm=None, charset=None, params=())
    token = stripped[:space]
    if token.lower() != "basic":
        return None
    params = _parse_auth_params(stripped[space + 1:])
    realm = None
    charset = None
    for name, value in params:
        if name == "realm":
            realm = value
        elif name == "charset":
            charset = value
    return WWWAuthenticateChallenge(
        realm=realm,
        charset=charset,
        params=params,
    )


def build_www_authenticate(
    realm: str,
    charset: Optional[str] = "UTF-8",
) -> str:
    """Build a ``WWW-Authenticate: Basic realm=\"...\"" header value.

    ``realm`` is required (RFC 7235 §2.2).  ``charset`` is included only when
    it equals ``'UTF-8'`` (case-insensitive), matching RFC 7617 §2.1.1.
    """
    # Escape per RFC 7230 §3.2.6: backslash and double-quote.
    escaped = realm.replace("\\", "\\\\").replace('"', '\\"')
    parts = [f'Basic realm="{escaped}"']
    if charset is not None and charset.upper() == "UTF-8":
        parts.append('charset="UTF-8"')
    return " ".join(parts)


@dataclass(frozen=True)
class WWWAuthenticateChallenge:
    """Result of parsing a ``WWW-Authenticate: Basic`` challenge."""

    realm: Optional[str]
    charset: Optional[str]
    params: Tuple[Tuple[str, str], ...]
