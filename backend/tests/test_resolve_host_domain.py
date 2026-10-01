import asyncio
import unittest
from types import SimpleNamespace
from unittest import mock

import main


class _Query:
    """Awaitable stand-in for a Tortoise queryset."""
    def __init__(self, rows):
        self.rows = rows

    def prefetch_related(self, *_):
        return self

    def __await__(self):
        async def _done():
            return self.rows
        return _done().__await__()


def _dom(id_, domain, company_id):
    return SimpleNamespace(id=id_, domain=domain, company_id=company_id)


def _resolve(domains, assets, host):
    domain_model = SimpleNamespace(filter=lambda **kw: _Query([d for d in domains if d.domain == kw["domain"]]))
    asset_model = SimpleNamespace(
        filter=lambda **kw: _Query([a for a in assets if a.value == kw["value"]]))
    with mock.patch.object(main, "Domain", domain_model), mock.patch.object(main, "Asset", asset_model):
        return asyncio.run(main._resolve_host_domain(host))


class ResolveHostDomainTests(unittest.TestCase):
    def test_apex_prefers_the_company_owned_row_over_an_orphan(self):
        # Regression: an orphan (quick scan) and a company row for the same
        # string used to be picked arbitrarily, hiding results from every
        # company view.
        orphan, owned = _dom(38, "example.com", None), _dom(71, "example.com", 31)
        self.assertIs(_resolve([orphan, owned], [], "example.com"), owned)
        self.assertIs(_resolve([owned, orphan], [], "example.com"), owned)

    def test_subdomain_resolves_through_its_asset_to_the_owned_domain(self):
        orphan, owned = _dom(38, "example.com", None), _dom(71, "example.com", 31)
        assets = [SimpleNamespace(value="app.example.com", domain=orphan),
                  SimpleNamespace(value="app.example.com", domain=owned)]
        self.assertIs(_resolve([orphan, owned], assets, "app.example.com"), owned)

    def test_only_an_orphan_is_still_resolved(self):
        orphan = _dom(8, "quickscan.example", None)
        self.assertIs(_resolve([orphan], [], "quickscan.example"), orphan)

    def test_unknown_host_is_none(self):
        self.assertIsNone(_resolve([], [], "nope.example"))

    def test_between_two_owned_rows_the_newest_wins(self):
        a, b = _dom(29, "shared.example", 13), _dom(77, "shared.example", 38)
        self.assertIs(_resolve([a, b], [], "shared.example"), b)


if __name__ == "__main__":
    unittest.main()
