import re
import unittest
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).parent
EXPECTED_PAGES = {
    "dashboard", "assessments", "incidents", "findings",
    "history", "reports", "policy", "settings",
}


class ShellParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.nav_pages = set()
        self.panel_pages = set()
        self.buttons_without_type = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "a" and "data-page" in attributes:
            self.nav_pages.add(attributes["data-page"])
        if "data-page-panel" in attributes:
            self.panel_pages.add(attributes["data-page-panel"])
        if tag == "button" and "type" not in attributes:
            self.buttons_without_type.append(attributes.get("id", "unnamed"))


class FrontendContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "index.html").read_text(encoding="utf-8")
        cls.javascript = (ROOT / "app.js").read_text(encoding="utf-8")
        cls.parser = ShellParser()
        cls.parser.feed(cls.html)

    def test_dom_ids_are_unique_and_javascript_references_exist(self):
        duplicates = [name for name, count in Counter(self.parser.ids).items() if count > 1]
        javascript_ids = set(re.findall(r"el\('([^']+)'\)", self.javascript))
        self.assertEqual(duplicates, [])
        self.assertEqual(javascript_ids - set(self.parser.ids), set())

    def test_navigation_and_page_panels_are_complete(self):
        self.assertEqual(self.parser.nav_pages, EXPECTED_PAGES)
        self.assertEqual(self.parser.panel_pages, EXPECTED_PAGES)
        self.assertIn("const PAGES=['dashboard','assessments','incidents','findings','history','reports','policy','settings']", self.javascript)

    def test_hash_navigation_supports_direct_and_history_navigation(self):
        self.assertIn("window.addEventListener('hashchange',applyRoute)", self.javascript)
        self.assertIn("history.replaceState(null,'','#'+page)", self.javascript)
        self.assertIn("return PAGES.includes(page)?page:'dashboard'", self.javascript)

    def test_interactive_controls_and_disclosures_are_semantic(self):
        self.assertEqual(self.parser.buttons_without_type, [])
        self.assertIn('<nav id="primary-nav">', self.html)
        self.assertIn('<details class="panel disclosure page-panel">', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn('class="skip-link"', self.html)


if __name__ == "__main__":
    unittest.main()
