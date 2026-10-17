"""Tests for http_basic_auth_header_parser.core.

All edge cases below correspond to branches actually implemented in
``core.py``.  The suite is deliberately narrow: it verifies the documented
contract, not a speculative one.
"""

import base64
import unittest

from http_basic_auth_header_parser import (
    BasicAuthHeader,
    parse_authorization,
    build_authorization,
    parse_www_authenticate,
    build_www_authenticate,
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


class TestParseAuthorization(unittest.TestCase):
    def test_simple_user_password(self):
        h = parse_authorization(f"Basic {_b64('alice:secret')}")
        self.assertEqual(h, BasicAuthHeader("alice", "secret", None))

    def test_scheme_case_insensitive(self):
        h = parse_authorization(f"basic {_b64('bob:pw')}")
        self.assertEqual(h, BasicAuthHeader("bob", "pw", None))

    def test_BASIC_uppercase(self):
        h = parse_authorization(f"BASIC {_b64('BOB:pw')}")
        self.assertEqual(h, BasicAuthHeader("BOB", "pw", None))

    def test_empty_password(self):
        h = parse_authorization(f"Basic {_b64('alice:')}")
        self.assertEqual(h, BasicAuthHeader("alice", "", None))

    def test_empty_username(self):
        h = parse_authorization(f"Basic {_b64(':pw')}")
        self.assertEqual(h, BasicAuthHeader("", "pw", None))

    def test_extra_whitespace_around_scheme(self):
        # RFC 7235: recipients MUST ignore linear whitespace.
        h = parse_authorization(f"  Basic   {_b64('a:b')}  ")
        self.assertEqual(h, BasicAuthHeader("a", "b", None))

    def test_internal_whitespace_in_base64(self):
        # Insert a space in the middle of the base64 token.
        raw = _b64("alice:secret")
        h = parse_authorization(f"Basic {raw[:4]} {raw[4:]}")
        self.assertEqual(h, BasicAuthHeader("alice", "secret", None))

    def test_unicode_username_password(self):
        h = parse_authorization(f"Basic {_b64('élé: päss')}")
        self.assertEqual(h, BasicAuthHeader("élé", " päss", None))

    def test_non_utf8_bytes_fallback_latin1(self):
        # 0xE9 alone is invalid UTF-8 but valid latin-1 ('é').
        raw = base64.b64encode(b"\xe9:pw").decode("ascii")
        h = parse_authorization(f"Basic {raw}")
        self.assertEqual(h, BasicAuthHeader("é", "pw", None))

    def test_missing_colon_returns_none(self):
        raw = base64.b64encode(b"nocolonhere").decode("ascii")
        self.assertIsNone(parse_authorization(f"Basic {raw}"))

    def test_wrong_scheme_returns_none(self):
        self.assertIsNone(parse_authorization(f"Bearer {_b64('a:b')}"))

    def test_not_base64_returns_none(self):
        self.assertIsNone(parse_authorization("Basic !!!notbase64!!!"))

    def test_empty_header_returns_none(self):
        self.assertIsNone(parse_authorization(""))

    def test_basic_only_no_credentials_returns_none(self):
        self.assertIsNone(parse_authorization("Basic"))

    def test_missing_padding_is_tolerated(self):
        # Drop trailing '=' padding — some clients do this.
        raw = _b64("alice:secret").rstrip("=")
        h = parse_authorization(f"Basic {raw}")
        self.assertEqual(h, BasicAuthHeader("alice", "secret", None))

    def test_round_trip_identity(self):
        for u, p in [("a", "b"), ("user", "p"), ("é", "ü"), ("x", "")]:
            built = build_authorization(u, p)
            parsed = parse_authorization(built)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed.user, u)
            self.assertEqual(parsed.password, p)


class TestBuildAuthorization(unittest.TestCase):
    def test_builds_basic_prefix(self):
        token = _b64("alice:secret")
        self.assertEqual(build_authorization("alice", "secret"), f"Basic {token}")

    def test_unicode_user_password_encoded_utf8(self):
        token = _b64("élé:secret")
        self.assertEqual(build_authorization("élé", "secret"), f"Basic {token}")


class TestParseWWWAuthenticate(unittest.TestCase):
    def test_realm_only(self):
        c = parse_www_authenticate('Basic realm="my realm"')
        self.assertEqual(c.realm, "my realm")
        self.assertIsNone(c.charset)

    def test_realm_and_charset(self):
        c = parse_www_authenticate('Basic realm="x", charset="UTF-8"')
        self.assertEqual(c.realm, "x")
        self.assertEqual(c.charset, "UTF-8")

    def test_case_insensitive_scheme(self):
        c = parse_www_authenticate('basic realm="x"')
        self.assertEqual(c.realm, "x")

    def test_no_params(self):
        c = parse_www_authenticate("Basic")
        self.assertIsNone(c.realm)
        self.assertIsNone(c.charset)

    def test_empty_returns_none(self):
        self.assertIsNone(parse_www_authenticate(""))

    def test_wrong_scheme_returns_none(self):
        self.assertIsNone(parse_www_authenticate('Bearer realm="x"'))

    def test_unquoted_param_value_tolerated(self):
        # Technically realm must be quoted, but we tolerate bare tokens.
        c = parse_www_authenticate("Basic realm=myrealm")
        self.assertEqual(c.realm, "myrealm")

    def test_realm_with_escaped_quote(self):
        c = parse_www_authenticate('Basic realm="a\\"b"')
        self.assertEqual(c.realm, 'a"b')


class TestBuildWWWAuthenticate(unittest.TestCase):
    def test_realm_and_charset_utf8(self):
        self.assertEqual(
            build_www_authenticate("myrealm"),
            'Basic realm="myrealm" charset="UTF-8"',
        )

    def test_non_utf8_charset_omitted(self):
        self.assertEqual(
            build_www_authenticate("r", charset="latin-1"),
            'Basic realm="r"',
        )

    def test_none_charset_omitted(self):
        self.assertEqual(
            build_www_authenticate("r", charset=None),
            'Basic realm="r"',
        )

    def test_quote_in_realm_escaped(self):
        self.assertEqual(
            build_www_authenticate('a"b'),
            'Basic realm="a\\"b" charset="UTF-8"',
        )

    def test_backslash_in_realm_escaped(self):
        self.assertEqual(
            build_www_authenticate("a\\b"),
            'Basic realm="a\\\\b" charset="UTF-8"',
        )


if __name__ == "__main__":
    unittest.main()
