# http-basic-auth-header-parser

Parses and constructs `Authorization` and `WWW-Authenticate` headers for the HTTP Basic authentication scheme, handling RFC 7617 charset and RFC 2045 base64 with whitespace tolerance.

## Usage

```python
from http_basic_auth_header_parser import (
    parse_authorization,
    build_authorization,
    parse_www_authenticate,
    build_www_authenticate,
)

# Request side
header = build_authorization("alice", "secret")
# -> 'Basic YWxpY2U6c2VjcmV0'

parsed = parse_authorization(header)
# parsed.user == 'alice', parsed.password == 'secret', parsed.charset is None

# Response side
challenge = build_www_authenticate("my-realm")
# -> 'Basic realm="my-realm" charset="UTF-8"'

c = parse_www_authenticate(challenge)
# c.realm == 'my-realm', c.charset == 'UTF-8'
```

## Why this exists

Real-world Basic-auth clients are noisy: they omit base64 padding, inject
internal whitespace into the token, and send credentials that aren't valid
UTF-8.  This library decodes the token leniently (stripping all whitespace
before base64-decoding, padding to a multiple of four) and decodes the
user-pass octets as UTF-8 with a latin-1 fallback.  That fallback is a
deliberate trade-off: it sacrifices strictness for round-trip identity, so
`parse(build(u, p)).user == u` holds for any string whose code points fit
in a single byte.  Unknown charsets other than `UTF-8` are not applied —
only the presence of the `charset` parameter from RFC 7617 is surfaced.

The awkward edge you will hit: if a client sends a password containing a
raw byte that is not valid UTF-8 (e.g. a lone `0xE9`), the parser returns a
latin-1 character rather than raising.  This keeps request handlers from
500-ing on malformed input, but it means you should not treat `user` or
`password` as guaranteed-clean UTF-8 if you forward them downstream.
