import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

from modules import admin_discovery as ad
from modules import port_scan as ps


def shell(path: str) -> bytes:
    """A Next.js-style app shell that echoes the requested URL twice and
    mentions 'login' somewhere in its bundle."""
    return (f'<html><link rel="canonical" href="https://x.example{path}">'
            f'<script id="__NEXT_DATA__">{{"page":"{path}","login":true}}</script>'
            + "x" * 34000 + "</html>").encode()


def resp(body: bytes, status=200):
    return SimpleNamespace(status_code=status, content=body,
                           headers={"content-type": "text/html; charset=utf-8"})


class SpaCatchAllTests(unittest.TestCase):
    def test_reflected_path_does_not_defeat_the_baseline(self):
        async def fake_afetch(url, **kw):
            return resp(shell("/" + url.split("/", 3)[3]))
        with mock.patch.object(ad, "afetch", fake_afetch):
            async def go():
                baseline = await ad._calibrate(None, "https://x.example")
                return [await ad._probe(None, "https://x.example", p, baseline)
                        for p in ("/actuator", "/admin", "/adminpanel", "/api-docs")]
            self.assertEqual(asyncio.run(go()), [None] * 4)

    def test_real_login_page_survives(self):
        login = b'<html><form><input type="password" name="password"></form></html>'

        async def fake_afetch(url, **kw):
            path = "/" + url.split("/", 3)[3]
            if path == "/admin":
                return resp(login)
            return resp(shell(path))
        with mock.patch.object(ad, "afetch", fake_afetch):
            async def go():
                baseline = await ad._calibrate(None, "https://x.example")
                return await ad._probe(None, "https://x.example", "/admin", baseline)
            hit = asyncio.run(go())
        self.assertIsNotNone(hit)
        self.assertEqual(hit["path"], "/admin")


class ClusterTests(unittest.TestCase):
    def hit(self, path, size, status=200):
        return {"path": path, "status": status, "size": size, "severity": "high"}

    def test_near_identical_sizes_are_dropped(self):
        found = [self.hit("/a", 34918), self.hit("/b", 34912), self.hit("/c", 34915), self.hit("/real", 5200)]
        kept, dropped = ad.drop_catch_all(found)
        self.assertEqual([f["path"] for f in kept], ["/real"])
        self.assertEqual(dropped, 3)

    def test_two_similar_hits_are_kept(self):
        found = [self.hit("/a", 9000), self.hit("/b", 9010)]
        self.assertEqual(ad.drop_catch_all(found), (found, 0))

    def test_401_is_never_part_of_a_cluster(self):
        found = [self.hit(p, 700, status=401) for p in ("/a", "/b", "/c", "/d")]
        self.assertEqual(ad.drop_catch_all(found), (found, 0))


def port(n, banner=""):
    return {"port": n, "service": "x", "state": "open", "banner": banner, "risky": n in (21, 23, 1433),
            "unauthenticated": False}


class EdgeWallTests(unittest.TestCase):
    def test_silent_wall_keeps_only_web_and_answering_ports(self):
        ports = [port(n) for n in range(100, 150)] + [port(80, "HTTP/1.1 503"), port(443)]
        kept, dropped = ps.drop_edge_wall(ports)
        self.assertEqual(sorted(p["port"] for p in kept), [80, 443])
        self.assertEqual(len(dropped), 50)

    def test_answering_service_inside_a_wall_is_kept(self):
        ports = [port(n) for n in range(100, 120)] + [port(22, "SSH-2.0-OpenSSH_9.2")]
        kept, _ = ps.drop_edge_wall(ports)
        self.assertIn(22, [p["port"] for p in kept])

    def test_few_open_ports_are_never_a_wall(self):
        ports = [port(21), port(25), port(80), port(443)]
        self.assertEqual(ps.drop_edge_wall(ports), (ports, []))

    def test_many_ports_that_do_greet_are_real(self):
        ports = [port(n, "220 hello") for n in range(100, 115)]
        self.assertEqual(ps.drop_edge_wall(ports), (ports, []))


if __name__ == "__main__":
    unittest.main()
