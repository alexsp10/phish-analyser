"""Brand impersonation: typosquats, homoglyphs and brand names in the wrong domain."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .urls import registrable_domain, to_unicode

# Characters that look like Latin letters (Cyrillic / Greek / IPA) plus digit swaps.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ӏ": "l",
        "ԛ": "q",
        "ԝ": "w",
        "ո": "n",
        "ս": "u",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "ν": "v",
        "ι": "i",
        "κ": "k",
        "τ": "t",
        "ε": "e",
        "υ": "u",
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "|": "l",
    }
)


def skeleton(text: str) -> str:
    """Collapse visually confusable spellings: 'pаypa1' (Cyrillic а, digit 1) -> 'paypal'."""
    text = unicodedata.normalize("NFKC", text).lower().translate(_CONFUSABLES)
    text = text.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    domains: tuple[str, ...]
    lookalike: tuple[str, ...] = ()

    @property
    def labels(self) -> set[str]:
        """Names checked for impersonation in domains.

        Defaults to the label of the first official domain (paypal.com -> paypal).
        Generic words such as 'live' (live.com) or 'me' (me.com) are deliberately
        not used: 'live-music.example' is not a Microsoft impersonation.
        """
        if self.lookalike:
            return set(self.lookalike)
        return {registrable_domain(self.domains[0]).split(".")[0]}


@dataclass(frozen=True)
class Impersonation:
    brand: str
    reason: str


class BrandCatalog:
    def __init__(self, brands: list[Brand]):
        self.brands = brands
        self.official = {registrable_domain(d) for b in brands for d in b.domains}

    @classmethod
    def load(cls, extra: str | Path | None = None) -> BrandCatalog:
        data = json.loads(resources.files("phishcheck").joinpath("brands.json").read_text(encoding="utf-8"))
        if extra:
            data.update(json.loads(Path(extra).read_text(encoding="utf-8")))
        brands = [
            Brand(
                name,
                tuple(k.lower() for k in spec.get("keywords", [])),
                tuple(d.lower() for d in spec["domains"]),
                tuple(n.lower() for n in spec.get("lookalike", [])),
            )
            for name, spec in data.items()
        ]
        return cls(brands)

    def is_official(self, host: str) -> bool:
        return registrable_domain(host) in self.official

    def brand_for_domain(self, host: str) -> Brand | None:
        registrable = registrable_domain(host)
        for brand in self.brands:
            if registrable in {registrable_domain(d) for d in brand.domains}:
                return brand
        return None

    def brands_named_in(self, text: str) -> list[Brand]:
        """Brands whose keyword appears as a whole word in ``text`` (e.g. a display name)."""
        lowered = text.lower()
        found = []
        for brand in self.brands:
            if any(re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", lowered) for k in brand.keywords):
                found.append(brand)
        return found

    def impersonation(self, host: str) -> Impersonation | None:
        """Does ``host`` imitate a known brand while not being one of its domains?"""
        host = host.lower().rstrip(".")
        if self.is_official(host):
            return None
        unicode_host = to_unicode(host)
        registrable = registrable_domain(unicode_host)
        sld = registrable.split(".")[0]
        sld_skeleton = skeleton(sld)
        sub_labels = unicode_host[: -len(registrable)].strip(".").split(".") if unicode_host != registrable else []
        sld_tokens = re.split(r"[-_]", sld)

        for brand in self.brands:
            for name in brand.labels:
                if sld == name:
                    return Impersonation(brand.name, f"uses the brand name '{name}' on an unofficial domain ending")
                if sld_skeleton == skeleton(name):
                    return Impersonation(brand.name, f"'{sld}' is a look-alike spelling of '{name}' (homoglyph)")
                if len(name) >= 6 and levenshtein(sld, name) <= (1 if len(name) < 9 else 2):
                    return Impersonation(brand.name, f"'{sld}' is one or two characters away from '{name}' (typosquat)")
                if name in sld_tokens or (len(name) >= 6 and name in sld):
                    return Impersonation(brand.name, f"brand name '{name}' is embedded in the domain '{registrable}'")
                if any(skeleton(token) == skeleton(name) for token in sld_tokens):
                    return Impersonation(
                        brand.name, f"a look-alike spelling of '{name}' is embedded in the domain '{registrable}'"
                    )
                if any(name == skeleton(label) or name in re.split(r"[-_]", skeleton(label)) for label in sub_labels):
                    return Impersonation(
                        brand.name,
                        f"brand name '{name}' appears in the subdomain, but the real domain is '{registrable}'",
                    )
        return None
