import unittest

import httpx

from modules import common
from modules.common import _materialized_headers


class MaterializedHeadersTests(unittest.TestCase):
    def test_non_ascii_and_repeated_headers_survive(self):
        resp = httpx.Response(200, headers=[
            (b"x-olaf", "⛄".encode()), (b"link", b"a"), (b"link", b"b"),
            (b"content-length", b"5"), (b"content-encoding", b"gzip"),
        ])
        out = _materialized_headers(resp)
        self.assertEqual(out["x-olaf"], "⛄")
        self.assertEqual(out.get_list("link"), ["a", "b"])
        self.assertNotIn("content-length", out)
        self.assertNotIn("content-encoding", out)


class UserAgentTests(unittest.TestCase):
    def test_default_when_unset_or_invalid(self):
        for bad in (None, "", "   ", "x" * 300, "bad\r\nInjected: 1", "ñandú", 5):
            common.set_user_agent(bad)
            self.assertEqual(common.user_agent(), common.DEFAULT_USER_AGENT, repr(bad))

    def test_custom_value_is_used_and_trimmed(self):
        common.set_user_agent("  Acme-Security-Scanner/2.0 (contact: sec@acme.test)  ")
        self.assertEqual(common.user_agent(), "Acme-Security-Scanner/2.0 (contact: sec@acme.test)")
        common.set_user_agent(None)

    def test_clients_carry_the_configured_agent(self):
        common.set_user_agent("Probe/9")
        client = common.make_client(proxy=None)
        self.assertEqual(client.headers["user-agent"], "Probe/9")
        client.close()
        common.set_user_agent(None)


if __name__ == "__main__":
    unittest.main()
