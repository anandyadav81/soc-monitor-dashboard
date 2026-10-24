"""Static checks on the frontend files. They need no browser. They catch two mistakes that happened before:
a // comment in the middle of a line that hides the code after it, and JavaScript that asks for an element
that is not in the HTML (the page then stops working)."""
import os
import re
import unittest

FRONT = os.path.join(os.path.dirname(__file__), "..", "frontend")


def read(*parts):
    with open(os.path.join(FRONT, *parts), encoding="utf-8") as f:
        return f.read()


class FrontendStaticTests(unittest.TestCase):
    def test_no_comment_hides_code_on_the_same_line(self):
        for name in ("app.js", "login.js"):
            for n, line in enumerate(read("js", name).splitlines(), 1):
                code = re.sub(r'"[^"\n]*"|\'[^\'\n]*\'|`[^`\n]*`', '""', line)  # ignore text inside quotes
                m = re.search(r"//(.*)$", code)
                if m:
                    self.assertFalse(re.search(r"[;{]\s*\$\(|\)\s*;\s*[A-Za-z$]", m.group(1)),
                                     f"{name} line {n}: code after a // comment is never run")

    def test_every_element_the_script_asks_for_exists(self):
        ids_in_html = set(re.findall(r'id="([A-Za-z0-9_-]+)"', read("index.html")))
        wanted = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', read("js", "app.js")))
        self.assertEqual(sorted(wanted - ids_in_html), [])
        login_ids = set(re.findall(r'id="([A-Za-z0-9_-]+)"', read("login.html")))
        self.assertEqual(sorted(set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', read("js", "login.js"))) - login_ids), [])

    def test_text_inputs_have_a_type(self):  # an input without type is drawn white in the dark theme
        for name in ("index.html", "login.html"):
            for tag in re.findall(r"<input\b[^>]*>", read(name)):
                self.assertIn("type=", tag, f"{name}: {tag}")


if __name__ == "__main__":
    unittest.main()
