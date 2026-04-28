"""
pipeline.py — Core NLP pipeline for the RSS Threat Intelligence Connector POC.

Stages:
  1. Feed collection       — feedparser + recency filter
  2. Entity extraction     — regex (CVEs, ATT&CK IDs, hashes, IPs) + GLiNER NER
  3. Relevance filtering   — entity shortcut, then DeBERTa zero-shot NLI classifier
  4. Full-text scraping    — trafilatura, inline, with RSS-summary fallback
  5. Sentence embedding    — sentence-transformers MiniLM
  6. Topic clustering      — entity fingerprint hard-constraint + cosine similarity
  7. Summarisation         — embedding-based extractive; optional DistilBART abstractive
  8. Source attribution    — timestamp, domain tier, attribution phrases, canonical URL

No OpenCTI dependency — designed to run and be validated standalone in the POC
harness before being integrated into the full connector.
"""

import calendar
import hashlib
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import feedparser
import numpy as np
import requests
import yaml
from bs4 import BeautifulSoup

logger = logging.getLogger("pipeline")

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_RE_TECHNIQUE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_RE_SENT_SPLIT = re.compile(r'(?<=[.!?])\s+(?=[A-Z"\u201c])')

_ATTRIBUTION_PHRASES = [
    "originally published on",
    "originally published at",
    "this article first appeared",
    "first reported by",
    "first published on",
    "republished from",
    "via ",
    "source:",
    "hat tip to",
    "h/t ",
    "reprinted from",
    "cross-posted from",
]

_GLINER_LABELS = [
    "malware family",
    "threat actor group",
    "victim organization",
    "affected software or product",
]

# Known security research firms, threat intelligence vendors, CERTs, and government
# security agencies. Entities matching these names (case-insensitive) are tagged
# `reporter` role and excluded from entity fingerprints and cluster titles.
_RESEARCHER_VENDORS: frozenset = frozenset({
    # Big research firms
    "unit 42", "unit42",
    "cisco talos", "talos",
    "shadowserver", "shadowserver foundation",
    "check point research", "checkpoint research", "checkpoint",
    "mandiant",
    "crowdstrike", "falcon overwatch",
    "google tag", "google threat analysis group", "google threat intelligence",
    "microsoft threat intelligence", "mstic",
    "microsoft security response center", "msrc",
    "recorded future",
    "secureworks", "counter threat unit", "ctu",
    "sentinelone labs", "sentinelone",
    "trend micro research", "trend micro",
    "proofpoint threat research", "proofpoint",
    "malwarebytes labs", "malwarebytes",
    "bitdefender",
    "eset research", "eset",
    "kaspersky", "kaspersky lab",
    "symantec threat hunter", "symantec", "broadcom symantec",
    "fortiguard labs", "fortiguard",
    "rapid7 labs", "rapid7",
    "tenable research", "tenable",
    "qualys research", "qualys",
    "wiz research", "wiz",
    "palo alto networks",
    # Government / CERT bodies
    "cisa", "us-cert", "cert",
    "nsa", "nsa cybersecurity",
    "cyber command", "uscybercom",
    # OT / ICS
    "dragos", "claroty", "nozomi networks",
    # Other reputable vendors
    "lumen", "black lotus labs",
    "sophos x-ops", "sophos",
    "huntress",
    "volexity",
    "elastic security labs", "elastic security",
    "team cymru",
    "abnormal security",
    "cofense",
    "cybersixgill",
    "intel 471",
    "eclypsium",
    "binarly",
    "flare",
})

# Maps article source domains to the canonical vendor name (must be in _RESEARCHER_VENDORS).
# Used to auto-tag self-referential mentions from research blogs.
_DOMAIN_TO_VENDOR: Dict[str, str] = {
    "unit42.paloaltonetworks.com":  "unit 42",
    "blog.talosintelligence.com":   "cisco talos",
    "talosintelligence.com":        "cisco talos",
    "talos-intelligence.com":       "cisco talos",
    "shadowserver.org":             "shadowserver",
    "research.checkpoint.com":      "check point research",
    "blog.checkpoint.com":          "check point research",
    "mandiant.com":                 "mandiant",
    "crowdstrike.com":              "crowdstrike",
    "adversary.crowdstrike.com":    "crowdstrike",
    "security.googleblog.com":      "google tag",
    "msrc.microsoft.com":           "msrc",
    "recordedfuture.com":           "recorded future",
    "secureworks.com":              "secureworks",
    "sentinelone.com":              "sentinelone labs",
    "trendmicro.com":               "trend micro",
    "proofpoint.com":               "proofpoint",
    "malwarebytes.com":             "malwarebytes",
    "bitdefender.com":              "bitdefender",
    "welivesecurity.com":           "eset research",
    "eset.com":                     "eset research",
    "securelist.com":               "kaspersky",
    "kaspersky.com":                "kaspersky",
    "symantec.com":                 "symantec",
    "fortiguard.com":               "fortiguard labs",
    "fortinet.com":                 "fortiguard labs",
    "rapid7.com":                   "rapid7",
    "tenable.com":                  "tenable",
    "wiz.io":                       "wiz research",
    "cisa.gov":                     "cisa",
    "dragos.com":                   "dragos",
    "claroty.com":                  "claroty",
    "nozominetworks.com":           "nozomi networks",
    "blog.lumen.com":               "lumen",
    "news.sophos.com":              "sophos",
    "huntress.com":                 "huntress",
    "volexity.com":                 "volexity",
    "elastic.co":                   "elastic security labs",
    "team-cymru.com":               "team cymru",
    "abnormalsecurity.com":         "abnormal security",
}

# NLI role hypotheses for entity role verification (suffix appended to candidate name).
# Order determines the label list passed to the classifier; roles are mapped back via suffix.
_ROLE_NLI_SUFFIXES: List[Tuple[str, str]] = [
    ("is a threat actor, APT group, or hacker group", "threat_actor"),
    ("is a victim organization",                      "victim"),
    ("is a malware family or malicious tool",          "malware"),
    ("is a software or technology product",            "product"),
    ("is a security vendor or research firm",          "reporter"),
    ("is not a relevant named entity",                 "not_an_entity"),
]

# Keywords used for rule-based category assignment (in priority order).
# Each tuple: (category_name, [title/description keywords])
_CATEGORY_RULES: List[Tuple[str, List[str]]] = [
    ("data-breach",      ["data breach", "data leak", "stolen data", "exposed data",
                          "leaked records", "compromised accounts", "data theft",
                          "records exposed", "information stolen", "claims breach",
                          "claims attack on", "hacked", " breach", " leaked"]),
    ("vulnerability",    ["vulnerability", "zero-day", "0-day", "patch tuesday",
                          "security advisory", "exploit", "cve-", " flaw",
                          "privilege escalation", "remote code execution", " rce",
                          "buffer overflow", "injection", "patches", "out-of-bounds"]),
    ("malware",          ["malware", "trojan", "backdoor", "rootkit", "spyware",
                          "worm", " virus", "loader", "stealer", "infostealer",
                          "dropper", " rat ", "remote access trojan", "ransomware",
                          "cryptominer", "botnet", "keylogger"]),
    ("ai-security",      ["artificial intelligence", "machine learning", " llm",
                          "large language model", "claude", "gpt-", "chatgpt",
                          "gemini", "anthropic", "openai", "ai model", "ai agent",
                          "agentic", "model context protocol", " mcp "]),
    ("policy-governance", ["regulation", "legislation", "compliance", "gdpr", "ccpa",
                           "nist", "law enforcement", "arrested", "indicted",
                           "charged with", "sentenced", "prison", " fbi ", " doj ",
                           "takedown", "seized", "sanctions", "court", "plea"]),
]

# Title keywords that identify roundup / digest articles.
# Roundup articles aggregate many separate events; they should not be allowed
# to magnetize unrelated articles via entity overlap in the clustering stage.
_ROUNDUP_TITLE_KEYWORDS: frozenset = frozenset({
    "patch tuesday",
    "week in review",
    "roundup",
    "recap",
    "digest",
    "threat roundup",
    "this week in",
    "in this week",
    "weekly",
    "this month in",
})

# ---------------------------------------------------------------------------
# Event-signature constants (Phase 6.2)
# ---------------------------------------------------------------------------

# Title/description keywords for rule-based event type classification.
# Checked in `classify_event_type`; order within each set is irrelevant.
_BREACH_KEYWORDS: frozenset = frozenset({
    "data breach", "data leak", "data stolen", "records exposed",
    "database leaked", "hacked", "unauthorized access", "compromised",
    "claims breach", "claims attack", "alleged breach",
    "stolen credentials", "exfiltrated", "disclosed",
})

_ARREST_KEYWORDS: frozenset = frozenset({
    "arrested", "indicted", "charged with", "sentenced to prison",
    "plea deal", "guilty plea", "extradited", "pleaded guilty",
    "criminal charges",
})

_RESEARCH_KEYWORDS: frozenset = frozenset({
    "researchers discovered", "researchers found", "analysis of",
    "technical analysis", "deep dive", "we discovered", "we investigated",
    "hunting for", "indicators of compromise", "new technique",
    "attributed to", "dissecting", "malware analysis",
})

_ADVISORY_KEYWORDS: frozenset = frozenset({
    "security advisory", "security bulletin", "urges users",
    "advises users", "patch now", "update now", "mitigate",
})

# Human-readable labels for event types used in cluster title formatting.
_EVENT_TYPE_LABELS: Dict[str, str] = {
    "breach":            "Breach",
    "vuln_disclosure":   "Vulnerability",
    "malware_campaign":  "Campaign",
    "arrest_indictment": "Arrest / Indictment",
    "product_release":   "Product Release",
    "research":          "Research",
    "advisory":          "Advisory",
    "commentary":        "Commentary",
    "unknown":           "Incident",
}

# SITREP top-level category mapping: NLI hypothesis text → internal label
_SITREP_TOPLEVEL_MAP: Dict[str, str] = {
    "cyberattack, data breach, or network intrusion":        "cyber-threats",
    "financial fraud, scam, or related criminal prosecution": "fraud",
    "artificial intelligence security threat":               "ai-threats",
    "software supply chain compromise":                      "supply-chain",
    "insider threat by a current or former employee or contractor": "insider-threats",
}

# SITREP cyber sub-category mapping: NLI hypothesis text → internal label
_SITREP_SUBCATS_MAP: Dict[str, str] = {
    "nation-state or advanced persistent threat actor": "apt",
    "ransomware attack or operator":                    "ransomware",
    "software vulnerability or security patch":         "vulnerability",
    "malware or malicious code":                        "malware",
    "data theft or unauthorized data exposure":         "data-breach",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EntityFingerprint:
    cves: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    malware: List[str] = field(default_factory=list)
    orgs: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)

    def has_regex_entities(self) -> bool:
        """True if any regex-derived (high-confidence) TI entity was found.

        Only CVEs and ATT&CK technique IDs qualify — both are structurally
        unambiguous patterns that cannot be mislabelled. GLiNER-extracted names
        (threat_actors, malware) are intentionally excluded because their role
        assignments are unreliable (see DESIGN.md v3.2).
        """
        return bool(self.cves or self.techniques)

    def has_ti_entities(self) -> bool:
        """True if any TI entity was found (regex or GLiNER)."""
        return bool(self.cves or self.techniques or self.threat_actors or self.malware)

    def overlaps(self, other: "EntityFingerprint") -> bool:
        """True if at least one significant entity appears in both fingerprints.

        Uses normalised substring matching so minor formatting differences
        (McGraw-Hill vs McGraw Hill, Kraken vs Kraken Exchange) still match.
        A minimum length of 4 characters prevents spurious substring matches
        on short tokens like "AT" appearing inside "ITAT Group".
        """
        for attr in ("cves", "threat_actors", "malware", "orgs", "products", "techniques"):
            self_vals = [_normalize_entity_text(e) for e in getattr(self, attr) if e]
            other_vals = [_normalize_entity_text(e) for e in getattr(other, attr) if e]
            for s in self_vals:
                for o in other_vals:
                    if len(s) >= 4 and len(o) >= 4 and (s == o or s in o or o in s):
                        return True
        return False

    def significant_terms(self) -> List[str]:
        """All entity strings useful for summary sentence boosting."""
        return self.cves + self.threat_actors + self.malware + self.orgs + self.products

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items() if v}

    def __len__(self) -> int:
        return sum(
            len(getattr(self, f))
            for f in ("cves", "techniques", "threat_actors", "malware", "orgs", "products")
        )


@dataclass
class EntityCandidate:
    """A GLiNER-extracted entity candidate pending role verification.

    `gliner_label` preserves the raw model output as a prior.
    `role` is updated by verify_entity_roles(); do not trust the initial value
    (which is derived mechanically from gliner_label).
    `confidence_tier` progresses: candidate → verified (NLI margin ≥ 0.15)
    or platform (authoritative OpenCTI match via anchor_candidates).
    `score` is the NLI margin for verified/candidate tiers, or 1.0 for platform/reporter.
    """
    name: str
    gliner_label: str     # raw GLiNER label — prior only
    role: str             # threat_actor | malware | victim | product | reporter | not_an_entity
    confidence_tier: str  # platform | verified | candidate
    score: float = 0.0


@dataclass
class EventSignature:
    """Structured event descriptor computed per article before clustering (Phase 6.2).

    Cluster keys are derived from (event_type, primary_subject_norm, time_bucket)
    rather than raw entity-name overlap, which prevents same-actor / different-victim
    over-merging and resolves actor aliases (BlackCat ≡ ALPHV) before they reach the
    bucket assignment step.

    Cluster key = (event_type, normalize(primary_subject))
    Two articles bucket together iff their keys match AND their publication dates
    are within `cluster_window_days` of each other.
    """
    event_type: str              # breach | vuln_disclosure | malware_campaign |
                                 #   arrest_indictment | product_release | research |
                                 #   advisory | commentary | unknown
    primary_subject: Optional[str]   # canonical focal entity (victim org, CVE, malware…)
    primary_subject_role: str        # victim | cve | malware | actor | product | none
    actor: Optional[str]             # canonical actor name (None for descriptors)
    actor_is_named: bool             # False for generic phrases ("Chinese hackers")
    time_bucket: date                # article.published.date() UTC day
    supporting: Set[str]             # other verified entity names mentioned


@dataclass
class Article:
    title: str
    link: str
    description: str
    published: datetime
    feed_title: str
    feed_url: str
    full_text: str = ""
    scrape_status: str = "pending"   # pending | success | failed | skipped
    entities: EntityFingerprint = field(default_factory=EntityFingerprint)
    entity_candidates: List[EntityCandidate] = field(default_factory=list)
    embedding: Optional[np.ndarray] = None
    relevance_score: float = 1.0
    relevance_method: str = "passthrough"   # entity | classifier | passthrough
    relevance_passed: bool = True
    category: str = "general"  # threat-actor | vulnerability | malware | data-breach | ai-security | policy-governance | general
    is_roundup: bool = False
    event_signature: Optional[EventSignature] = None
    sitrep_categories: List[str] = field(default_factory=list)   # cyber-threats | fraud | ai-threats | supply-chain | insider-threats | general
    sitrep_cyber_subcats: List[str] = field(default_factory=list)  # apt | ransomware | vulnerability | malware | data-breach

    @property
    def article_id(self) -> str:
        return hashlib.sha256(self.link.encode()).hexdigest()[:16]

    @property
    def source_domain(self) -> str:
        return urlparse(self.link).netloc.removeprefix("www.")

    @property
    def best_text(self) -> str:
        """Full scraped text when available, otherwise RSS description."""
        return self.full_text or self.description or self.title

    @property
    def text_for_classification(self) -> str:
        """Short representation used for relevance classification."""
        desc = self.description or self.full_text[:300]
        return f"{self.title}. {desc}"[:512]


@dataclass
class SubEvent:
    """A sub-event within a cluster, partitioned by victim organization."""
    victim_org: str   # empty string = articles with no victim org
    anchor: Article
    see_also: List[Article] = field(default_factory=list)


@dataclass
class ClusterResult:
    cluster_id: str
    articles: List[Article]
    entity_fingerprint: EntityFingerprint
    embedding_centroid: np.ndarray
    original_source_domain: str = ""
    original_source_method: str = ""
    summary_extractive: str = ""
    summary_abstractive: str = ""
    category: str = "general"
    sitrep_categories: List[str] = field(default_factory=list)
    sitrep_cyber_subcats: List[str] = field(default_factory=list)
    sub_events: List[SubEvent] = field(default_factory=list)
    event_signature: Optional[EventSignature] = None

    @property
    def title(self) -> str:
        # Phase 6.2: use event signature title when available (v3.3 decision #5).
        if self.event_signature is not None:
            return _format_signature_title(self.event_signature, self.articles)

        # Fallback: entity-based title for clusters without signatures.
        fp = self.entity_fingerprint
        cats = self.sitrep_cyber_subcats

        if "vulnerability" in cats and fp.cves:
            parts = [fp.cves[0]]
            if fp.threat_actors:
                parts.append(fp.threat_actors[0])
            return " — ".join(parts)

        if "data-breach" in cats and fp.orgs:
            parts = [fp.orgs[0]]
            if fp.threat_actors:
                parts.append(fp.threat_actors[0])
            elif fp.malware:
                parts.append(fp.malware[0])
            return " — ".join(parts)

        if "malware" in cats and fp.malware:
            parts = [fp.malware[0]]
            if fp.threat_actors:
                parts.append(fp.threat_actors[0])
            return " — ".join(parts)

        parts: List[str] = []
        if fp.threat_actors:
            parts.append(fp.threat_actors[0])
        if fp.malware:
            parts.append(fp.malware[0])
        elif fp.cves:
            parts.append(fp.cves[0])
        if not parts:
            if fp.cves:
                return fp.cves[0]
            if fp.orgs:
                return fp.orgs[0]
            return (self.articles[0].title or "Unknown Event")[:80]
        return " — ".join(parts[:2])

    @property
    def earliest_published(self) -> datetime:
        return min(a.published for a in self.articles)


@dataclass
class FilteredArticle:
    article: Article
    reason: str
    score: float


@dataclass
class PipelineResult:
    run_at: datetime
    config: Dict
    clusters: List[ClusterResult]
    filtered_articles: List[FilteredArticle]
    stats: Dict


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _normalize_entity_text(text: str) -> str:
    """Normalise an entity string for fuzzy overlap comparison."""
    return re.sub(r'[-_\s]+', ' ', text.lower()).strip()


def split_sentences(text: str, min_len: int = 30) -> List[str]:
    """Split text into sentences using punctuation + capitalisation heuristic."""
    raw = _RE_SENT_SPLIT.split(text.strip())
    return [s.strip() for s in raw if len(s.strip()) >= min_len]


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom < 1e-9:
        return 0.0
    return float(np.dot(a, b) / denom)


def clean_html(raw: str) -> str:
    """Strip HTML tags and collapse whitespace."""
    if not raw:
        return ""
    text = BeautifulSoup(raw, "html.parser").get_text(separator=" ")
    return re.sub(r'\s+', ' ', text).strip()


def parse_published(entry) -> datetime:
    pp = entry.get("published_parsed")
    if pp:
        try:
            return datetime.fromtimestamp(calendar.timegm(pp), tz=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def merge_fingerprints(fps: List[EntityFingerprint]) -> EntityFingerprint:
    """Union all entities across multiple fingerprints."""
    return EntityFingerprint(
        cves=sorted({c for fp in fps for c in fp.cves}),
        techniques=sorted({t for fp in fps for t in fp.techniques}),
        threat_actors=sorted({a for fp in fps for a in fp.threat_actors}),
        malware=sorted({m for fp in fps for m in fp.malware}),
        orgs=sorted({o for fp in fps for o in fp.orgs}),
        products=sorted({p for fp in fps for p in fp.products}),
    )


# ---------------------------------------------------------------------------
# Phase 6.2: Event-signature helpers
# ---------------------------------------------------------------------------

def _is_actor_named(name: str) -> bool:
    """True if name looks like a proper noun (has at least one capitalised token)."""
    return bool(name) and any(t[0].isupper() for t in name.split() if t)


def canonicalize_actor(name: str, alias_table: Dict[str, str]) -> str:
    """Return the canonical actor name from the alias table, or the original."""
    return alias_table.get(name.lower(), name)


def _format_signature_title(
    sig: EventSignature, articles: List["Article"]
) -> str:
    """Build the cluster title per v3.3 design decision #5.

    Format: "{actor} — {event_type_label} — {primary_subject}" with graceful
    collapse when actor or primary_subject is absent.
    """
    event_label = _EVENT_TYPE_LABELS.get(sig.event_type, "Incident")
    parts: List[str] = []

    if sig.actor and sig.actor_is_named:
        parts.append(sig.actor)
    parts.append(event_label)
    if sig.primary_subject:
        parts.append(sig.primary_subject)

    if len(parts) <= 1:
        # No useful structured signal — use the seed article headline.
        return (articles[0].title if articles else "Unknown Event")[:80]
    return " — ".join(parts)


def classify_event_type(art: "Article") -> str:
    """Rule-based event type classifier using entity fingerprint + title keywords.

    Priority order (higher = checked first):
      1. CVE present                       → vuln_disclosure
      2. Arrest/indictment keywords        → arrest_indictment
      3. Victim org + breach keywords      → breach
      4. Breach keywords (no victim)       → breach
      5. Malware present                   → malware_campaign
      6. Research keywords                 → research
      7. Advisory keywords                 → advisory
      8. Fallback                          → unknown
    """
    fp = art.entities
    text_lower = f"{art.title} {art.description}".lower()

    if fp.cves:
        return "vuln_disclosure"

    if any(kw in text_lower for kw in _ARREST_KEYWORDS):
        return "arrest_indictment"

    if any(kw in text_lower for kw in _BREACH_KEYWORDS):
        return "breach"

    if fp.malware:
        return "malware_campaign"

    if any(kw in text_lower for kw in _RESEARCH_KEYWORDS):
        return "research"

    if any(kw in text_lower for kw in _ADVISORY_KEYWORDS):
        return "advisory"

    return "unknown"


def pick_primary_subject(
    art: "Article",
    event_type: str,
    alias_table: Dict[str, str],
) -> Tuple[Optional[str], str]:
    """Return (primary_subject_canonical, primary_subject_role) for an article.

    Rules keyed on event_type (design v3.1):
      breach            → first verified victim org
      vuln_disclosure   → first CVE; fallback to product
      malware_campaign  → first malware family; fallback to named actor
      arrest_indictment → first named threat actor (the arrested party)
      research          → malware family (v3.3 #4), then technique, then product
      advisory / release→ CVE, then product
      commentary/unknown→ None (singleton by similarity)
    """
    fp = art.entities

    if event_type == "vuln_disclosure":
        if fp.cves:
            return fp.cves[0].upper(), "cve"
        if fp.products:
            return fp.products[0], "product"
        return None, "none"

    if event_type == "breach":
        if fp.orgs:
            return fp.orgs[0], "victim"
        return None, "none"

    if event_type == "malware_campaign":
        if fp.malware:
            return fp.malware[0], "malware"
        # Actor-as-primary fallback for actor-only campaign stories.
        if fp.threat_actors:
            canonical = canonicalize_actor(fp.threat_actors[0], alias_table)
            if _is_actor_named(canonical):
                return canonical, "actor"
        return None, "none"

    if event_type == "arrest_indictment":
        if fp.threat_actors:
            canonical = canonicalize_actor(fp.threat_actors[0], alias_table)
            return canonical, "actor"
        if fp.orgs:
            return fp.orgs[0], "victim"
        return None, "none"

    if event_type == "research":
        if fp.malware:
            return fp.malware[0], "malware"
        if fp.techniques:
            return fp.techniques[0], "product"
        if fp.products:
            return fp.products[0], "product"
        return None, "none"

    if event_type in ("advisory", "product_release"):
        if fp.cves:
            return fp.cves[0].upper(), "cve"
        if fp.products:
            return fp.products[0], "product"
        return None, "none"

    return None, "none"


def compute_event_signatures(
    articles: List["Article"],
    alias_table: Optional[Dict[str, str]] = None,
) -> List["Article"]:
    """Compute and attach an EventSignature to each article (Stage 5b).

    Must run after embed_articles() and verify_entity_roles() so that
    art.entities contains only role-verified, canonical entity strings.
    alias_table maps lowercase_alias → canonical_name (from OpenCTI IntrusionSets).
    """
    if alias_table is None:
        alias_table = {}

    for art in articles:
        event_type = classify_event_type(art)
        primary_subject, primary_subject_role = pick_primary_subject(
            art, event_type, alias_table
        )

        fp = art.entities
        actor: Optional[str] = None
        actor_is_named = False
        if fp.threat_actors:
            raw = fp.threat_actors[0]
            canonical = canonicalize_actor(raw, alias_table)
            if _is_actor_named(canonical):
                actor = canonical
                actor_is_named = True

        # Supporting: remaining verified entities not already the primary subject.
        supporting: Set[str] = set()
        for name in fp.threat_actors[1:]:
            c = canonicalize_actor(name, alias_table)
            if _is_actor_named(c):
                supporting.add(c)
        for name in fp.malware:
            if primary_subject_role != "malware" or name != primary_subject:
                supporting.add(name)
        for name in fp.orgs:
            if primary_subject_role != "victim" or name != primary_subject:
                supporting.add(name)

        art.event_signature = EventSignature(
            event_type=event_type,
            primary_subject=primary_subject,
            primary_subject_role=primary_subject_role,
            actor=actor,
            actor_is_named=actor_is_named,
            time_bucket=art.published.date(),
            supporting=supporting,
        )

    type_counts: Dict[str, int] = {}
    for art in articles:
        t = art.event_signature.event_type if art.event_signature else "?"
        type_counts[t] = type_counts.get(t, 0) + 1
    logger.info(f"Event signatures: {dict(sorted(type_counts.items()))}")
    return articles


# ---------------------------------------------------------------------------
# Lazy model loaders — each model is loaded once on first use
# ---------------------------------------------------------------------------

_embedder = None
_gliner = None
_classifier = None
_summarizer = None


def get_embedder(config: Dict):
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        model_name = config.get("embedding_model", "all-MiniLM-L6-v2")
        logger.info(f"Loading embedding model: {model_name}")
        _embedder = SentenceTransformer(model_name)
    return _embedder


def get_gliner(config: Dict):
    global _gliner
    if _gliner is None and config.get("gliner_enabled", True):
        try:
            from gliner import GLiNER
            model_name = config.get("ner_model", "urchade/gliner_medium-v2.1")
            logger.info(f"Loading GLiNER model: {model_name}")
            _gliner = GLiNER.from_pretrained(model_name)
        except Exception as exc:
            logger.warning(f"GLiNER unavailable ({exc}); NER limited to regex")
    return _gliner


def get_classifier(config: Dict):
    global _classifier
    if _classifier is None and config.get("classifier_enabled", True):
        try:
            from transformers import pipeline as hf_pipeline
            import warnings
            model_name = config.get(
                "classifier_model",
                "MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli",
            )
            logger.info(f"Loading zero-shot classifier: {model_name}")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                _classifier = hf_pipeline(
                    "zero-shot-classification",
                    model=model_name,
                    device=-1,
                )
        except Exception as exc:
            logger.warning(f"Classifier unavailable ({exc}); all articles pass relevance filter")
    return _classifier


def get_summarizer(config: Dict):
    global _summarizer
    if _summarizer is None and config.get("summarization_enabled", False):
        try:
            from transformers import pipeline as hf_pipeline
            import warnings
            model_name = config.get("summarization_model", "sshleifer/distilbart-cnn-12-6")
            logger.info(f"Loading summarisation model: {model_name}")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                _summarizer = hf_pipeline(
                    "summarization",
                    model=model_name,
                    device=-1,
                )
        except Exception as exc:
            logger.warning(f"Summarisation model unavailable ({exc}); using extractive only")
    return _summarizer


# ---------------------------------------------------------------------------
# Stage 1: Feed collection
# ---------------------------------------------------------------------------

def _fetch_single_feed(
    feed_cfg: Dict,
    global_max_age: int,
    max_per_feed: int,
) -> List[Article]:
    """Fetch one RSS feed and return its Articles. Called from a thread pool."""
    url = feed_cfg.get("url", "")
    name = feed_cfg.get("name", url)
    if not url:
        return []

    feed_max_age = int(feed_cfg.get("max_age_days", global_max_age))
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=feed_max_age)
        if feed_max_age > 0 else None
    )
    require_link = feed_cfg.get("require_link_contains", "")
    exclude_title_kws = [kw.lower() for kw in feed_cfg.get("exclude_title_keywords", [])]

    results: List[Article] = []
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; TI-RSS-POC/2.0)"},
            timeout=30,
        )
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        feed_title = feed.feed.get("title", name)
        skipped = 0

        for entry in feed.entries[:max_per_feed]:
            pub = parse_published(entry)
            if cutoff and pub < cutoff:
                skipped += 1
                continue

            title = clean_html(entry.get("title", ""))
            link = entry.get("link", "")
            if not title or not link:
                continue

            if require_link and require_link not in link:
                skipped += 1
                continue
            if exclude_title_kws and any(kw in title.lower() for kw in exclude_title_kws):
                skipped += 1
                continue

            raw_desc = entry.get("summary") or entry.get("description") or ""
            description = clean_html(raw_desc)[:1000]

            results.append(Article(
                title=title,
                link=link,
                description=description,
                published=pub,
                feed_title=feed_title,
                feed_url=url,
            ))

        msg = f"  {name}: {len(results)} articles"
        if skipped:
            msg += f" ({skipped} skipped)"
        logger.info(msg)

    except Exception as exc:
        logger.error(f"Failed to fetch {name}: {exc}")

    return results


def collect_articles(config: Dict) -> List[Article]:
    """Fetch all configured RSS feeds in parallel and return a flat list of Articles."""
    global_max_age = int(config.get("max_age_days", 3))
    max_per_feed = int(config.get("max_articles_per_feed", 30))

    feed_cfgs = [
        ({"url": fc} if isinstance(fc, str) else fc)
        for fc in config.get("feeds", [])
        if fc
    ]

    articles: List[Article] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_fetch_single_feed, fc, global_max_age, max_per_feed): fc
            for fc in feed_cfgs
        }
        for future in as_completed(futures):
            try:
                articles.extend(future.result())
            except Exception as exc:
                logger.error(f"Feed fetch raised unexpectedly: {exc}")

    # Deduplicate by URL
    seen: set = set()
    unique: List[Article] = []
    for a in articles:
        if a.link not in seen:
            seen.add(a.link)
            unique.append(a)

    logger.info(f"Collected {len(unique)} unique articles from {len(feed_cfgs)} feeds")
    return unique


# ---------------------------------------------------------------------------
# Stage 2: Entity extraction
# ---------------------------------------------------------------------------

def _regex_fingerprint(text: str) -> EntityFingerprint:
    """Extract structured entities via regex — fast, zero model cost."""
    return EntityFingerprint(
        cves=[m.upper() for m in sorted(set(_RE_CVE.findall(text)))],
        techniques=sorted(set(_RE_TECHNIQUE.findall(text))),
    )


def extract_entities_batch(articles: List[Article], config: Dict) -> List[Article]:
    """
    Run regex extraction on all articles, then GLiNER in batch.

    Regex results (CVEs, ATT&CK IDs) go directly into art.entities — they are
    structurally unambiguous and need no role verification.

    GLiNER results are stored as EntityCandidate objects in art.entity_candidates
    with role assignments treated as priors only.  verify_entity_roles() updates
    these priors and rebuilds art.entities from the verified output.
    """
    _LABEL_TO_PRIOR_ROLE = {
        "threat actor group":       "threat_actor",
        "malware family":           "malware",
        "victim organization":      "victim",
        "affected software or product": "product",
    }

    # Regex pass (free; results are authoritative — no verification needed)
    for art in articles:
        text = f"{art.title} {art.description}"
        art.entities = _regex_fingerprint(text)

    # GLiNER pass
    gliner = get_gliner(config)
    if gliner is None:
        return articles

    logger.info(f"Running GLiNER NER on {len(articles)} articles...")
    texts = [f"{a.title} {a.description}"[:2000] for a in articles]

    import warnings
    try:
        # GLiNER 0.2.x+ preferred API
        batch_results = gliner.inference(texts, _GLINER_LABELS, threshold=0.4)
    except AttributeError:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                batch_results = gliner.batch_predict_entities(texts, _GLINER_LABELS, threshold=0.4)
        except AttributeError:
            batch_results = [
                gliner.predict_entities(t, _GLINER_LABELS, threshold=0.4) for t in texts
            ]

    for art, entities in zip(articles, batch_results):
        seen_names: set = set()
        candidates: List[EntityCandidate] = []
        for ent in entities:
            label = ent.get("label", "")
            val = ent.get("text", "").strip()
            # Must be a recognised label, non-trivial length, and start with a letter
            # (filters NLP artifacts like "legitimate plugin business")
            if not val or len(val) < 2 or label not in _LABEL_TO_PRIOR_ROLE:
                continue
            if not val[0].isalpha():
                continue
            name_key = val.lower()
            if name_key in seen_names:
                continue
            seen_names.add(name_key)
            candidates.append(EntityCandidate(
                name=val,
                gliner_label=label,
                role=_LABEL_TO_PRIOR_ROLE[label],  # prior — updated by verify_entity_roles
                confidence_tier="candidate",
                score=float(ent.get("score", 0.0)),
            ))
        art.entity_candidates = candidates

    return articles


# ---------------------------------------------------------------------------
# Stage 2c/2d: Entity role verification
# ---------------------------------------------------------------------------

def verify_entity_roles(articles: List[Article], config: Dict) -> List[Article]:
    """
    Verify the role of every GLiNER candidate in art.entity_candidates.

    Three stages per candidate (short-circuit on first match):
      1. Reporter list — name is in _RESEARCHER_VENDORS → role="reporter", tier="verified"
      2. Domain inference — article's source domain maps to a vendor name and the
         candidate is a variant of that name → role="reporter", tier="verified"
      3. NLI role verification — DeBERTa zero-shot across six role hypotheses
         (same model already loaded for relevance filtering).  Margin ≥ 0.15 required
         to assign a non-ambiguous role; below margin → role="not_an_entity".

    After all candidates are classified, rebuilds art.entities from the verified
    candidates only (reporter and not_an_entity excluded).
    """
    classifier = get_classifier(config)

    total_candidates = 0
    total_nli = 0
    total_verified = 0

    for art in articles:
        if not art.entity_candidates:
            continue

        # Identify vendor associated with this article's source domain (if any)
        vendor_from_domain = _DOMAIN_TO_VENDOR.get(art.source_domain, "")
        vendor_tokens: set = {
            t for t in vendor_from_domain.split() if len(t) >= 4
        } if vendor_from_domain else set()

        nli_queue: List[EntityCandidate] = []

        for cand in art.entity_candidates:
            total_candidates += 1
            name_lower = cand.name.lower()

            # Stage 1 — static reporter list
            if name_lower in _RESEARCHER_VENDORS:
                cand.role = "reporter"
                cand.confidence_tier = "verified"
                cand.score = 1.0
                continue

            # Stage 2 — source-domain self-reference inference
            if vendor_tokens and any(t in name_lower for t in vendor_tokens):
                cand.role = "reporter"
                cand.confidence_tier = "verified"
                cand.score = 1.0
                continue

            nli_queue.append(cand)

        # Stage 3 — NLI role verification for remaining candidates
        if nli_queue:
            article_text = art.text_for_classification
            for cand in nli_queue:
                total_nli += 1
                if classifier is None:
                    # No classifier available — keep GLiNER prior as low-confidence candidate
                    continue

                candidate_labels = [
                    f"{cand.name} {suffix}" for suffix, _ in _ROLE_NLI_SUFFIXES
                ]
                label_to_role = {
                    f"{cand.name} {suffix}": role
                    for suffix, role in _ROLE_NLI_SUFFIXES
                }
                try:
                    result = classifier(
                        article_text,
                        candidate_labels=candidate_labels,
                        hypothesis_template="In this article, {}.",
                        multi_label=False,
                    )
                    top_label: str = result["labels"][0]
                    top_score: float = result["scores"][0]
                    second_score: float = (
                        result["scores"][1] if len(result["scores"]) > 1 else 0.0
                    )
                    margin = top_score - second_score
                    verified_role = label_to_role.get(top_label, "not_an_entity")

                    if verified_role == "not_an_entity" or margin < 0.15:
                        cand.role = "not_an_entity"
                        cand.confidence_tier = "candidate"
                    else:
                        cand.role = verified_role
                        cand.confidence_tier = "verified"
                        total_verified += 1
                    cand.score = margin
                except Exception as exc:
                    logger.debug(f"Role NLI failed for '{cand.name}': {exc}")
                    cand.role = "not_an_entity"
                    cand.confidence_tier = "candidate"

        # Rebuild EntityFingerprint from verified and platform-anchored candidates only.
        # Candidates with role "not_an_entity" or "reporter", or confidence_tier "candidate",
        # do not enter the fingerprint — they appear in the SITREP footer at most.
        threat_actors: List[str] = []
        malware_list: List[str] = []
        orgs: List[str] = []
        products: List[str] = []

        for cand in art.entity_candidates:
            if cand.confidence_tier == "candidate":
                continue
            if cand.role in ("not_an_entity", "reporter"):
                continue
            if cand.role == "threat_actor":
                threat_actors.append(cand.name)
            elif cand.role == "malware":
                malware_list.append(cand.name)
            elif cand.role == "victim":
                orgs.append(cand.name)
            elif cand.role == "product":
                products.append(cand.name)

        # Update the existing EntityFingerprint (preserve regex-derived CVEs/techniques)
        art.entities.threat_actors = sorted(set(threat_actors))
        art.entities.malware = sorted(set(malware_list))
        art.entities.orgs = sorted(set(orgs))
        art.entities.products = sorted(set(products))

    if total_candidates:
        logger.info(
            f"Role verification: {total_nli} NLI calls, "
            f"{total_verified}/{total_candidates} candidates assigned a verified role"
        )
    return articles


# ---------------------------------------------------------------------------
# Stage 3: Relevance filtering
# ---------------------------------------------------------------------------

def filter_relevance(
    articles: List[Article], config: Dict
) -> Tuple[List[Article], List[FilteredArticle]]:
    """
    Two-tier relevance gate.

    Tier 1 (free): Articles with TI entities pass immediately.
    Tier 2 (ML):   Remaining articles are classified by DeBERTa zero-shot NLI.
    """
    threshold = float(config.get("relevance_threshold", 0.55))
    skip_if_entities = config.get("relevance_skip_if_has_entities", True)

    # Tier 1 — entity shortcut
    passed: List[Article] = []
    needs_classification: List[Article] = []

    for art in articles:
        if skip_if_entities and art.entities.has_regex_entities():
            art.relevance_score = 1.0
            art.relevance_method = "entity"
            art.relevance_passed = True
            passed.append(art)
        else:
            needs_classification.append(art)

    logger.info(
        f"Relevance tier-1: {len(passed)} passed via entities, "
        f"{len(needs_classification)} sent to classifier"
    )

    # Tier 2 — zero-shot classifier
    filtered: List[FilteredArticle] = []
    classifier = get_classifier(config)

    if needs_classification:
        if classifier is None:
            # No classifier available — pass everything through
            for art in needs_classification:
                art.relevance_score = 0.5
                art.relevance_method = "passthrough"
                art.relevance_passed = True
            passed.extend(needs_classification)
        else:
            logger.info(f"Running zero-shot classifier on {len(needs_classification)} articles...")
            texts = [a.text_for_classification for a in needs_classification]
            candidate_labels = [
                "cybersecurity threat or vulnerability",
                "product review or consumer guide",
            ]

            # Process in batches of 16 to manage memory
            batch_size = 16
            all_results = []
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                try:
                    results = classifier(
                        batch,
                        candidate_labels=candidate_labels,
                        hypothesis_template="This text is about {}.",
                        multi_label=False,
                    )
                    # Pipeline returns a single dict for single input, list for multiple
                    if isinstance(results, dict):
                        results = [results]
                    all_results.extend(results)
                except Exception as exc:
                    logger.warning(f"Classifier batch failed: {exc}; passing batch through")
                    all_results.extend([None] * len(batch))

            for art, result in zip(needs_classification, all_results):
                if result is None:
                    art.relevance_score = 0.5
                    art.relevance_method = "passthrough"
                    art.relevance_passed = True
                    passed.append(art)
                    continue

                labels = result["labels"]
                scores = result["scores"]
                pos_label = "cybersecurity threat or vulnerability"
                pos_score = scores[labels.index(pos_label)]

                art.relevance_score = round(pos_score, 3)
                art.relevance_method = "classifier"
                art.relevance_passed = pos_score >= threshold

                if art.relevance_passed:
                    passed.append(art)
                else:
                    filtered.append(FilteredArticle(
                        article=art,
                        reason=f"classifier score {pos_score:.2f} < threshold {threshold}",
                        score=pos_score,
                    ))

    logger.info(
        f"Relevance filtering complete: {len(passed)} passed, {len(filtered)} dropped"
    )
    return passed, filtered


# ---------------------------------------------------------------------------
# Stage 4: Full-text scraping
# ---------------------------------------------------------------------------

def _scrape_one(art: Article, session, timeout: int) -> None:
    """Scrape a single article in place. Modifies art.full_text and art.scrape_status."""
    try:
        import trafilatura
    except ImportError:
        art.scrape_status = "skipped"
        return

    try:
        resp = session.get(art.link, timeout=timeout, allow_redirects=True)
        if not resp.ok:
            logger.debug(f"Scrape HTTP {resp.status_code} for {art.link}")
            art.scrape_status = "failed"
            return

        text = trafilatura.extract(
            resp.text,
            url=art.link,
            include_comments=False,
            include_tables=False,
            no_fallback=False,
        )
        if not text or len(text) < 100:
            art.scrape_status = "failed"
            return

        # Sanity check: paywall/SSO redirect pages return non-article HTML.
        # Require at least one substantive title token (≥4 chars) to appear in the text.
        title_tokens = {t.lower() for t in art.title.split() if len(t) >= 4}
        if title_tokens and not any(t in text.lower() for t in title_tokens):
            logger.debug(f"Scrape rejected (title tokens absent): {art.link}")
            art.scrape_status = "failed"
            return

        art.full_text = text
        art.scrape_status = "success"
    except Exception as exc:
        logger.debug(f"Scrape failed for {art.link}: {exc}")
        art.scrape_status = "failed"


def scrape_articles(articles: List[Article], config: Dict) -> List[Article]:
    """
    Scrape full article text in parallel via curl_cffi (Chrome TLS impersonation)
    + trafilatura extraction.

    curl_cffi replicates Chrome's JA3/JA4 TLS fingerprint at the socket level,
    bypassing bot-detection systems that block requests/httpx. Falls back to
    requests.Session if curl_cffi is unavailable.
    """
    try:
        import trafilatura  # noqa: F401 — verify installed before spawning threads
    except ImportError:
        logger.warning("trafilatura not installed; skipping full-text scraping")
        for art in articles:
            art.scrape_status = "skipped"
        return articles

    timeout = int(config.get("scrape_timeout", 15))
    logger.info(f"Scraping full text for {len(articles)} articles (parallel)...")

    try:
        from curl_cffi import requests as cffi_requests
        session = cffi_requests.Session(impersonate="chrome124")
        logger.debug("Scraping with curl_cffi (Chrome TLS impersonation)")
    except ImportError:
        logger.warning("curl_cffi not available; falling back to requests")
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        })

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_scrape_one, art, session, timeout): art for art in articles}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                logger.debug(f"Scrape worker raised: {exc}")

    success = sum(1 for a in articles if a.scrape_status == "success")
    logger.info(f"Scraping: {success}/{len(articles)} succeeded")
    return articles


# ---------------------------------------------------------------------------
# Stage 5: Sentence embedding
# ---------------------------------------------------------------------------

def embed_articles(articles: List[Article], config: Dict) -> List[Article]:
    """Compute sentence embeddings for all articles (batched)."""
    embedder = get_embedder(config)
    logger.info(f"Embedding {len(articles)} articles...")

    texts = [f"{a.title}. {(a.description or a.full_text)[:400]}" for a in articles]
    embeddings = embedder.encode(texts, batch_size=32, show_progress_bar=False)

    for art, emb in zip(articles, embeddings):
        art.embedding = emb.astype(np.float32)

    return articles


# ---------------------------------------------------------------------------
# Stage 5b: Category assignment
# ---------------------------------------------------------------------------

def assign_categories(articles: List[Article], config: Dict) -> List[Article]:
    """
    Assign a TI category to each article using entity fingerprint (highest priority)
    then title/description keyword matching.

    Priority order:
      1. Has named threat actors in fingerprint  → threat-actor
      2. Has CVEs or ATT&CK techniques           → vulnerability
      3. Has malware families in fingerprint     → malware
      4. Keyword match in title+description      → first matching category
      5. Fallback                                → general
    """
    if not config.get("category_constraint_enabled", True):
        return articles

    roundup_count = 0
    for art in articles:
        fp = art.entities

        # Roundup detection: articles aggregating many events skip entity-overlap
        # fast-path in clustering to prevent them becoming "cluster magnets".
        title_lower = art.title.lower()
        if len(fp.cves) >= 4 or any(kw in title_lower for kw in _ROUNDUP_TITLE_KEYWORDS):
            art.is_roundup = True
            roundup_count += 1

        # Entity-based priority (most reliable signal)
        if fp.threat_actors:
            art.category = "threat-actor"
            continue
        if fp.cves or fp.techniques:
            art.category = "vulnerability"
            continue
        if fp.malware:
            art.category = "malware"
            continue

        # Keyword-based fallback
        text_lower = f"{art.title} {art.description}".lower()
        assigned = False
        for category, keywords in _CATEGORY_RULES:
            if any(kw in text_lower for kw in keywords):
                art.category = category
                assigned = True
                break
        if not assigned:
            art.category = "general"

    counts: Dict[str, int] = {}
    for art in articles:
        counts[art.category] = counts.get(art.category, 0) + 1
    logger.info(f"Category assignment: {dict(sorted(counts.items()))}")
    if roundup_count:
        logger.info(f"Roundup detection: {roundup_count} articles flagged as roundups")
    return articles


def categories_compatible(cat1: str, cat2: str) -> bool:
    """
    True if two articles/clusters may be merged based on their categories.

    Rules:
    - 'general' is always compatible with any category (no category signal = no constraint).
    - 'data-breach' and 'threat-actor' are mutually compatible: the same incident is
      frequently covered from the attacker's perspective (threat-actor) in one article
      and from the victim's perspective (data-breach) in another. Blocking this merge
      would split the same story across two clusters.
    - All other category pairs must match exactly.
    """
    if cat1 == "general" or cat2 == "general":
        return True
    if {cat1, cat2} == {"data-breach", "threat-actor"}:
        return True
    return cat1 == cat2


# ---------------------------------------------------------------------------
# Stage 6: Topic clustering
# ---------------------------------------------------------------------------

def _cluster_id(seed_article: Article) -> str:
    sig = seed_article.event_signature
    if sig and sig.primary_subject:
        key = f"{sig.event_type}|{_normalize_entity_text(sig.primary_subject)}"
    else:
        fp = seed_article.entities
        key = "|".join(sorted(fp.cves + fp.threat_actors + fp.malware)) or seed_article.article_id
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def cluster_articles(articles: List[Article], config: Dict) -> List[ClusterResult]:
    """
    Bucket-first event-centric clustering (Phase 6.2 / v3).

    Each article is first assigned a bucket key derived from its EventSignature:
        key = (event_type, normalize(primary_subject))

    Articles sharing a key whose publication dates fall within `cluster_window_days`
    of each other are merge candidates.  Within candidates, cosine similarity ≥
    `cluster_min_similarity_entity_match` (default 0.55) confirms the merge.

    Articles with no primary subject (unknown / commentary types) fall back to a
    pure similarity-based path using the higher `cluster_min_similarity` threshold.

    Actor aliases are already resolved in `compute_event_signatures`, so different
    spellings of the same actor (BlackCat / ALPHV) land in the same bucket
    automatically — no cross-bucket merge logic is needed.
    """
    threshold_confirm = float(config.get("cluster_min_similarity_entity_match", 0.55))
    threshold_fallback = float(config.get("cluster_min_similarity", 0.72))
    window_days = int(config.get("cluster_window_days", 2))

    sorted_arts = sorted(
        [a for a in articles if a.embedding is not None],
        key=lambda a: a.published,
    )

    clusters: List[ClusterResult] = []

    def _merge_into(cluster: ClusterResult, art: Article) -> None:
        n = len(cluster.articles)
        cluster.embedding_centroid = (
            (cluster.embedding_centroid * n + art.embedding) / (n + 1)
        ).astype(np.float32)
        cluster.articles.append(art)
        cluster.entity_fingerprint = merge_fingerprints(
            [a.entities for a in cluster.articles]
        )
        if cluster.category == "general" and art.category != "general":
            cluster.category = art.category

    for art in sorted_arts:
        sig = art.event_signature
        best: Optional[ClusterResult] = None
        best_sim: float = -1.0

        # --- Bucketed path: article has a clear primary subject ---
        if (
            sig is not None
            and sig.primary_subject is not None
            and sig.event_type not in ("unknown", "commentary")
        ):
            art_key = (sig.event_type, _normalize_entity_text(sig.primary_subject))

            for cluster in clusters:
                c_sig = cluster.event_signature
                if c_sig is None or c_sig.primary_subject is None:
                    continue
                c_key = (c_sig.event_type, _normalize_entity_text(c_sig.primary_subject))
                if art_key != c_key:
                    continue
                # Time-window check: publication dates must be within ±window_days
                days_diff = abs(
                    (art.published.date() - cluster.earliest_published.date()).days
                )
                if days_diff > window_days:
                    continue
                sim = cosine_similarity(art.embedding, cluster.embedding_centroid)
                if sim >= threshold_confirm and sim > best_sim:
                    best_sim = sim
                    best = cluster

        # --- Fallback path: no primary subject → pure similarity ---
        else:
            for cluster in clusters:
                sim = cosine_similarity(art.embedding, cluster.embedding_centroid)
                if sim >= threshold_fallback and sim > best_sim:
                    best_sim = sim
                    best = cluster

        if best is not None:
            _merge_into(best, art)
            logger.debug(
                f"Merged '{art.title[:60]}' → '{best.title}' (sim={best_sim:.3f})"
            )
        else:
            clusters.append(ClusterResult(
                cluster_id=_cluster_id(art),
                articles=[art],
                entity_fingerprint=art.entities,
                embedding_centroid=art.embedding.copy(),
                category=art.category,
                event_signature=sig,
            ))

    singleton_count = sum(1 for c in clusters if len(c.articles) == 1)
    logger.info(
        f"Clustering: {len(sorted_arts)} articles → {len(clusters)} clusters "
        f"({singleton_count} singletons; "
        f"confirm≥{threshold_confirm}, fallback≥{threshold_fallback}, "
        f"window±{window_days}d)"
    )
    return clusters


# ---------------------------------------------------------------------------
# Stage 7: Summarisation
# ---------------------------------------------------------------------------

def _deduplicate_sentences(
    sentences: List[str], embedder, threshold: float = 0.92
) -> List[str]:
    """Remove near-duplicate sentences using cosine similarity."""
    if len(sentences) <= 1:
        return sentences

    embeddings = embedder.encode(sentences, show_progress_bar=False)
    kept: List[str] = []
    kept_embs: List[np.ndarray] = []

    for sent, emb in zip(sentences, embeddings):
        if kept_embs:
            sims = [cosine_similarity(emb, k) for k in kept_embs]
            if max(sims) >= threshold:
                continue
        kept.append(sent)
        kept_embs.append(emb.astype(np.float32))

    return kept


def summarize_extractive(cluster: ClusterResult, config: Dict) -> str:
    """
    Score each sentence in the cluster by similarity to the embedding centroid.
    Sentences containing named entities receive a relevance boost.
    Returns the top-K sentences in their original order.
    """
    n_sentences = int(config.get("summary_max_sentences_extractive", 6))
    embedder = get_embedder(config)

    all_sentences: List[str] = []
    for art in cluster.articles:
        all_sentences.extend(split_sentences(art.best_text))

    if not all_sentences:
        return cluster.articles[0].title if cluster.articles else ""

    # Cap to prevent slow embedding on very large clusters
    all_sentences = all_sentences[:200]
    deduped = _deduplicate_sentences(all_sentences, embedder)

    if not deduped:
        return all_sentences[0] if all_sentences else ""

    embeddings = embedder.encode(deduped, show_progress_bar=False)
    centroid = cluster.embedding_centroid
    terms = {t.lower() for t in cluster.entity_fingerprint.significant_terms()}

    scored: List[Tuple[float, int, str]] = []
    for i, (sent, emb) in enumerate(zip(deduped, embeddings)):
        score = cosine_similarity(emb, centroid)
        if terms and any(t in sent.lower() for t in terms):
            score += 0.15
        scored.append((score, i, sent))

    top = sorted(scored, reverse=True)[:n_sentences]
    top_ordered = sorted(top, key=lambda x: x[1])
    return " ".join(s for _, _, s in top_ordered)


def summarize_abstractive(cluster: ClusterResult, config: Dict) -> str:
    """Run DistilBART over the extractive summary to produce a fluent abstract."""
    summarizer = get_summarizer(config)
    if summarizer is None or not cluster.summary_extractive:
        return ""

    input_text = cluster.summary_extractive
    max_len = int(config.get("summary_max_length_tokens", 150))
    min_len = max(20, max_len // 4)

    try:
        result = summarizer(
            input_text,
            max_length=max_len,
            min_length=min_len,
            do_sample=False,
        )
        return result[0].get("summary_text", "").strip()
    except Exception as exc:
        logger.debug(f"Abstractive summarisation failed: {exc}")
        return ""


# ---------------------------------------------------------------------------
# Stage 8: Original source attribution
# ---------------------------------------------------------------------------

def _check_canonical_url(url: str, timeout: int = 8) -> Optional[str]:
    """
    Fetch the article page and look for a canonical URL pointing to a different domain.
    Returns the canonical domain if it differs from the article's own domain, else None.
    """
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; TI-RSS-POC/2.0)"},
            timeout=timeout,
            allow_redirects=True,
        )
        soup = BeautifulSoup(resp.text, "html.parser")

        canonical = None
        tag = soup.find("link", rel="canonical")
        if tag and tag.get("href"):
            canonical = tag["href"]
        if not canonical:
            og = soup.find("meta", property="og:url")
            if og and og.get("content"):
                canonical = og["content"]

        if canonical:
            canonical_domain = urlparse(canonical).netloc.removeprefix("www.")
            article_domain = urlparse(url).netloc.removeprefix("www.")
            if canonical_domain and canonical_domain != article_domain:
                return canonical_domain
    except Exception:
        pass
    return None


def attribute_source(cluster: ClusterResult, config: Dict) -> Tuple[str, str]:
    """
    Identify the most likely original source for a cluster.
    Returns (domain, method_description).
    """
    primary_sources = set(config.get("primary_sources", []))
    check_canonical = config.get("check_canonical_url", False)

    # Check if any article comes from a known primary source
    for art in sorted(cluster.articles, key=lambda a: a.published):
        if art.source_domain in primary_sources:
            return art.source_domain, "primary_source_list"

    # Check attribution phrases in article text
    for art in cluster.articles:
        text_lower = (art.full_text or art.description).lower()
        for phrase in _ATTRIBUTION_PHRASES:
            if phrase in text_lower:
                # Return the earliest article that isn't the one containing the phrase
                candidates = [a for a in cluster.articles if a is not art]
                if candidates:
                    earliest = min(candidates, key=lambda a: a.published)
                    return earliest.source_domain, f"attribution_phrase: '{phrase.strip()}'"

    # Optional canonical URL check (adds HTTP requests)
    if check_canonical:
        for art in sorted(cluster.articles, key=lambda a: a.published):
            canonical_domain = _check_canonical_url(art.link)
            if canonical_domain:
                return canonical_domain, "canonical_url_tag"

    # Default: earliest-published article is most likely the originator
    earliest = min(cluster.articles, key=lambda a: a.published)
    return earliest.source_domain, "earliest_timestamp"


# ---------------------------------------------------------------------------
# Stage 3b: SITREP multi-label classification
# ---------------------------------------------------------------------------

def classify_sitrep(articles: List[Article], config: Dict) -> List[Article]:
    """
    Assign SITREP category labels to each article using two passes of DeBERTa
    zero-shot NLI (same model already loaded for relevance filtering).

    Pass 1 — top-level categories (cyber-threats, fraud, ai-threats, supply-chain,
              insider-threats), threshold: sitrep_threshold (default 0.40).
    Pass 2 — cyber sub-categories (apt, ransomware, vulnerability, malware,
              data-breach) only for articles tagged cyber-threats,
              threshold: sitrep_cyber_subcat_threshold (default 0.45).

    Entity fingerprint shortcuts bypass Pass 1 for high-confidence cases:
      - CVEs present           → pre-tag cyber-threats + vulnerability
      - Named threat actors    → pre-tag cyber-threats + apt
    """
    threshold_top = float(config.get("sitrep_threshold", 0.40))
    threshold_sub = float(config.get("sitrep_cyber_subcat_threshold", 0.45))

    # --- Entity fingerprint shortcuts (no classifier cost) ---
    for art in articles:
        fp = art.entities
        if fp.cves:
            art.sitrep_categories = list({"cyber-threats", *art.sitrep_categories})
            art.sitrep_cyber_subcats = list({"vulnerability", *art.sitrep_cyber_subcats})
        if fp.threat_actors:
            art.sitrep_categories = list({"cyber-threats", *art.sitrep_categories})
            art.sitrep_cyber_subcats = list({"apt", *art.sitrep_cyber_subcats})

    needs_pass1 = [art for art in articles if not art.sitrep_categories]

    classifier = get_classifier(config)
    if classifier is None:
        for art in articles:
            if not art.sitrep_categories:
                art.sitrep_categories = ["general"]
        return articles

    # --- Pass 1: top-level categories ---
    if needs_pass1:
        logger.info(
            f"SITREP Pass 1: classifying {len(needs_pass1)} articles "
            f"for top-level categories (threshold={threshold_top})..."
        )
        texts = [a.text_for_classification for a in needs_pass1]
        top_labels = list(_SITREP_TOPLEVEL_MAP.keys())

        batch_size = 16
        all_results: List = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            try:
                results = classifier(
                    batch,
                    candidate_labels=top_labels,
                    hypothesis_template="This article is about {}.",
                    multi_label=True,
                )
                if isinstance(results, dict):
                    results = [results]
                all_results.extend(results)
            except Exception as exc:
                logger.warning(f"SITREP Pass 1 batch failed: {exc}")
                all_results.extend([None] * len(batch))

        for art, result in zip(needs_pass1, all_results):
            if result is None:
                art.sitrep_categories = ["general"]
                continue
            assigned = [
                _SITREP_TOPLEVEL_MAP[label]
                for label, score in zip(result["labels"], result["scores"])
                if score >= threshold_top
            ]
            # Fraud false-positive reduction (Phase 1 follow-up):
            # Articles with CVEs or named threat actors are almost never about
            # financial fraud — the "criminal prosecution" part of the hypothesis
            # produces false positives on CVE/APT articles.  Remove the fraud tag
            # when the article has high-confidence TI entities.
            if "fraud" in assigned and art.entities.has_ti_entities():
                assigned = [c for c in assigned if c != "fraud"]
            art.sitrep_categories = assigned if assigned else ["general"]

    # --- Pass 2: cyber sub-categories ---
    needs_pass2 = [
        art for art in articles
        if "cyber-threats" in art.sitrep_categories and not art.sitrep_cyber_subcats
    ]
    if needs_pass2:
        logger.info(
            f"SITREP Pass 2: classifying {len(needs_pass2)} cyber-threat articles "
            f"for sub-categories (threshold={threshold_sub})..."
        )
        texts = [a.text_for_classification for a in needs_pass2]
        sub_labels = list(_SITREP_SUBCATS_MAP.keys())

        batch_size = 16
        all_results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            try:
                results = classifier(
                    batch,
                    candidate_labels=sub_labels,
                    hypothesis_template="This article describes {}.",
                    multi_label=True,
                )
                if isinstance(results, dict):
                    results = [results]
                all_results.extend(results)
            except Exception as exc:
                logger.warning(f"SITREP Pass 2 batch failed: {exc}")
                all_results.extend([None] * len(batch))

        for art, result in zip(needs_pass2, all_results):
            if result is None:
                continue
            subcats = [
                _SITREP_SUBCATS_MAP[label]
                for label, score in zip(result["labels"], result["scores"])
                if score >= threshold_sub
            ]
            art.sitrep_cyber_subcats = subcats

    # Log summary
    from collections import Counter
    cat_counts: Counter = Counter(
        cat for art in articles for cat in art.sitrep_categories
    )
    logger.info(f"SITREP categories: {dict(sorted(cat_counts.items()))}")
    return articles


# ---------------------------------------------------------------------------
# Stage 5b: Sub-event grouping
# ---------------------------------------------------------------------------

def compute_sub_events(clusters: List[ClusterResult]) -> List[ClusterResult]:
    """
    Within each multi-article cluster, partition articles by victim organization
    into sub-events.  Handles the "same actor, different target" pattern (e.g.
    a ShinyHunters cluster containing McGraw-Hill and Amtrak breaches) without
    requiring separate clusters per incident.

    Algorithm:
    1. Collect distinct victim org entities across the cluster (normalized).
    2. For each distinct victim, collect articles mentioning it.
    3. Articles mentioning no victim org fall into a catch-all sub-event.
    4. Each sub-event anchor = earliest article for that victim; rest = See Also.

    Single-victim clusters (or clusters with no victim orgs) are left unmodified.
    """
    for cluster in clusters:
        if len(cluster.articles) <= 1:
            continue

        # Collect distinct victim orgs (normalised for comparison, preserve original)
        seen_norms: List[str] = []
        distinct_orgs: List[str] = []
        for art in cluster.articles:
            for org in art.entities.orgs:
                norm = _normalize_entity_text(org)
                if norm not in seen_norms:
                    seen_norms.append(norm)
                    distinct_orgs.append(org)

        if len(distinct_orgs) <= 1:
            continue  # nothing to partition

        sub_events: List[SubEvent] = []
        assigned_ids: set = set()

        for org in distinct_orgs:
            org_norm = _normalize_entity_text(org)
            org_articles = [
                art for art in cluster.articles
                if any(_normalize_entity_text(o) == org_norm for o in art.entities.orgs)
            ]
            if not org_articles:
                continue
            anchor = min(org_articles, key=lambda a: a.published)
            see_also = [a for a in org_articles if a is not anchor]
            sub_events.append(SubEvent(victim_org=org, anchor=anchor, see_also=see_also))
            for art in org_articles:
                assigned_ids.add(art.article_id)

        # Unassigned articles (no victim org entity) → unnamed sub-event
        unassigned = [a for a in cluster.articles if a.article_id not in assigned_ids]
        if unassigned:
            anchor = min(unassigned, key=lambda a: a.published)
            see_also = [a for a in unassigned if a is not anchor]
            sub_events.append(SubEvent(victim_org="", anchor=anchor, see_also=see_also))

        if len(sub_events) > 1:
            cluster.sub_events = sub_events
            logger.debug(
                f"Sub-events: cluster '{cluster.title}' → {len(sub_events)} sub-events "
                f"({[se.victim_org or '(none)' for se in sub_events]})"
            )

    sub_event_clusters = sum(1 for c in clusters if c.sub_events)
    if sub_event_clusters:
        logger.info(f"Sub-event grouping: {sub_event_clusters} clusters partitioned")
    return clusters


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

def run_pipeline(
    config: Dict,
    known_urls: Optional[Set[str]] = None,
    alias_table: Optional[Dict[str, str]] = None,
) -> PipelineResult:
    """Execute all pipeline stages and return a PipelineResult for reporting."""
    t_start = time.time()
    stats: Dict = {}

    # Stage 1 — collect
    articles = collect_articles(config)
    stats["articles_fetched"] = len(articles)

    # Skip articles already ingested in a previous run. Previously-seen articles
    # remain in OpenCTI from when they were first processed; their observables are
    # already linked to that run's SITREP Report via update=True bundle pushes.
    if known_urls:
        new_articles = [a for a in articles if a.link not in known_urls]
        stats["articles_seen"] = len(articles) - len(new_articles)
        articles = new_articles
        if stats["articles_seen"]:
            logger.info(
                f"Skipping {stats['articles_seen']} already-ingested articles "
                f"({len(articles)} new this run)"
            )

    if not articles:
        logger.warning("No articles collected; check feed URLs and max_age_days")
        return PipelineResult(
            run_at=datetime.now(timezone.utc),
            config=config,
            clusters=[],
            filtered_articles=[],
            stats={**stats, "elapsed_seconds": 0},
        )

    # Stage 2 — entity extraction (regex fingerprint + GLiNER candidates)
    articles = extract_entities_batch(articles, config)

    # Stage 3 — relevance filtering
    # Tier 1 uses regex-derived entities (CVEs/techniques) only — not GLiNER output.
    # This is intentional: GLiNER roles are unverified at this point.
    relevant, filtered = filter_relevance(articles, config)
    stats["articles_filtered"] = len(filtered)
    stats["articles_relevant"] = len(relevant)

    if not relevant:
        logger.warning("All articles were filtered out; try lowering relevance_threshold")
        return PipelineResult(
            run_at=datetime.now(timezone.utc),
            config=config,
            clusters=[],
            filtered_articles=filtered,
            stats={**stats, "clusters": 0, "elapsed_seconds": round(time.time() - t_start, 1)},
        )

    # Stage 2c/2d — entity role verification (runs on relevant articles only)
    # Updates art.entity_candidates with verified roles and rebuilds art.entities.
    # Runs here (after relevance filtering) so NLI work is skipped for filtered articles.
    relevant = verify_entity_roles(relevant, config)

    # Stage 4 — scraping (optional)
    if config.get("scraping_enabled", True):
        relevant = scrape_articles(relevant, config)
        stats["scrape_success"] = sum(1 for a in relevant if a.scrape_status == "success")

    # Stage 5 — embedding
    relevant = embed_articles(relevant, config)

    # Stage 5a — internal category assignment (still used for cluster.category field)
    relevant = assign_categories(relevant, config)

    # Stage 3b — SITREP multi-label classification
    relevant = classify_sitrep(relevant, config)

    # Stage 5b — event signature computation (bucket keys for Phase 6.2 clustering)
    relevant = compute_event_signatures(relevant, alias_table)

    # Stage 6 — bucket-first clustering (v3; sub-event partitioning retired)
    clusters = cluster_articles(relevant, config)
    stats["clusters"] = len(clusters)
    stats["singleton_clusters"] = sum(1 for c in clusters if len(c.articles) == 1)

    # Promote SITREP categories from articles to cluster level (union of all articles)
    for cluster in clusters:
        cat_set: set = set()
        subcat_set: set = set()
        for art in cluster.articles:
            cat_set.update(art.sitrep_categories)
            subcat_set.update(art.sitrep_cyber_subcats)
        cluster.sitrep_categories = sorted(cat_set - {"general"}) or ["general"]
        cluster.sitrep_cyber_subcats = sorted(subcat_set)

    # Stages 7–8 — summarise and attribute
    logger.info("Summarising clusters and attributing sources...")
    for cluster in clusters:
        cluster.summary_extractive = summarize_extractive(cluster, config)
        if config.get("summarization_enabled", False):
            cluster.summary_abstractive = summarize_abstractive(cluster, config)
        cluster.original_source_domain, cluster.original_source_method = (
            attribute_source(cluster, config)
        )

    stats["elapsed_seconds"] = round(time.time() - t_start, 1)
    logger.info(
        f"Pipeline complete in {stats['elapsed_seconds']}s — "
        f"{stats['clusters']} clusters from {stats['articles_relevant']} articles"
    )

    return PipelineResult(
        run_at=datetime.now(timezone.utc),
        config=config,
        clusters=sorted(clusters, key=lambda c: len(c.articles), reverse=True),
        filtered_articles=filtered,
        stats=stats,
    )
