"""raptor/audit/htmlread.py: reads one HTML page into plain facts (title, meta tags, links, forms, scripts ...) with the standard library only."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

_SCRIPT_CAP = 20000          # inline script text kept per page (tag snippets are near the top; this keeps memory small)


class Page:
    def __init__(self, base: str):
        self.base = base
        self.title = ""
        self.lang = ""
        self.meta: dict = {}          # name / property (lower case) -> content
        self.links: list = []         # {href (absolute), text}
        self.scripts: list = []       # absolute src addresses
        self.inline_scripts: list = []
        self.forms: list = []         # {action, method, inputs:[{type,name}], textarea, submit}
        self.imgs: list = []          # absolute src addresses
        self.iframes: list = []
        self.rels: list = []          # {rel, href}
        self.h1 = 0
        self.text_len = 0
        self.ldjson = 0
        self.microdata = False
        self.ids: set = set()
        self.raw = ""

    def has_rel(self, name: str) -> bool:
        return any(name in (r["rel"] or "").lower().split() for r in self.rels)

    def meta_value(self, key: str) -> str:
        return (self.meta.get(key.lower()) or "").strip()

    @property
    def script_blob(self) -> str:
        return "\n".join(self.scripts + self.inline_scripts)

    @property
    def js_heavy(self) -> bool:
        """The page is mostly built by scripts in the browser, so a plain read sees almost no content: an absence on such a page proves nothing."""
        framework = bool(self.ids & {"root", "app", "__next", "__nuxt", "___gatsby", "svelte"}) or any(k in self.raw[:200000].lower() for k in ("ng-version", "data-reactroot", "data-v-app", "__next_data__", "window.__nuxt__"))
        return self.text_len < 400 and (framework or len(self.scripts) >= 3)


class _Reader(HTMLParser):
    def __init__(self, page: Page):
        super().__init__(convert_charrefs=True)
        self.p = page
        self._title = False
        self._a = None
        self._script = None            # None, or [type, buffer]
        self._skip = 0                 # inside style / noscript / template
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        p = self.p
        if a.get("id"):
            p.ids.add(a["id"].lower())
        if "itemscope" in a or "itemtype" in a:
            p.microdata = True
        if tag == "html":
            p.lang = a.get("lang", "")
        elif tag == "title":
            self._title = True
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key and "content" in a and key not in p.meta:
                p.meta[key] = a["content"]
        elif tag == "link":
            if a.get("href"):
                p.rels.append({"rel": a.get("rel", ""), "href": urljoin(p.base, a["href"])})
        elif tag == "a":
            if a.get("href"):
                self._a = {"href": urljoin(p.base, a["href"].strip()) if not re.match(r"^(mailto:|tel:|javascript:|#)", a["href"].strip(), re.I) else a["href"].strip(), "text": ""}
        elif tag == "script":
            if a.get("src"):
                p.scripts.append(urljoin(p.base, a["src"]))
            self._script = [a.get("type", "").lower(), []]
        elif tag in ("style", "noscript", "template"):
            self._skip += 1
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": [], "textarea": False, "submit": False}
            p.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            kind = (a.get("type") or "text").lower()
            if kind in ("submit", "image"):
                self._form["submit"] = True
            elif kind not in ("hidden", "button", "reset"):
                self._form["inputs"].append({"type": kind, "name": (a.get("name") or a.get("id") or a.get("placeholder") or "").lower()})
        elif tag == "textarea" and self._form is not None:
            self._form["textarea"] = True
        elif tag == "button" and self._form is not None:
            if (a.get("type") or "submit").lower() == "submit":
                self._form["submit"] = True
        elif tag == "img":
            src = a.get("src") or a.get("data-src") or ""
            if src and not src.startswith("data:"):
                p.imgs.append(urljoin(p.base, src))
        elif tag == "iframe":
            if a.get("src"):
                p.iframes.append(urljoin(p.base, a["src"]))
        elif tag == "h1":
            p.h1 += 1

    def handle_endtag(self, tag):
        p = self.p
        if tag == "title":
            self._title = False
        elif tag == "a" and self._a is not None:
            self._a["text"] = " ".join(self._a["text"].split())[:200]
            p.links.append(self._a)
            self._a = None
        elif tag == "script" and self._script is not None:
            kind, buf = self._script
            text = "".join(buf)
            if "ld+json" in kind:
                p.ldjson += 1
            elif text.strip():
                p.inline_scripts.append(text[:_SCRIPT_CAP])
            self._script = None
        elif tag in ("style", "noscript", "template") and self._skip:
            self._skip -= 1
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        p = self.p
        if self._title:
            p.title += data
        if self._a is not None:
            self._a["text"] += data
        if self._script is not None:
            self._script[1].append(data)
        elif not self._skip:
            p.text_len += len(data.strip())


def read(html: str, base: str) -> Page:
    page = Page(base)
    page.raw = html or ""
    try:
        _Reader(page).feed(page.raw)
    except Exception:       # a badly broken page still yields what was read so far
        pass
    page.title = " ".join(page.title.split())
    return page
