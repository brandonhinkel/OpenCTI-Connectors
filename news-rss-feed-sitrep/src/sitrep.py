"""
sitrep.py — SITREP narrative generator.

Produces the HTML content for the OpenCTI Report content tab.  Sections are
organised by top-level SITREP category (Cyber Threats, Fraud, AI Threats,
Supply Chain, Insider Threats), with multi-article clusters rendered as named
story cards and sub-events partitioned by victim organisation.

The output uses only inline styles and standard HTML elements (h1–h3, p, ul,
li, a, strong, em, span) so it renders correctly in OpenCTI's CKEditor content
box, which does not process embedded <style> blocks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Set

if TYPE_CHECKING:
    from pipeline import Article, ClusterResult, EntityCandidate, PipelineResult

# ---------------------------------------------------------------------------
# SITREP section ordering and display names
# ---------------------------------------------------------------------------

_TOPLEVEL_ORDER = [
    "cyber-threats",
    "fraud",
    "ai-threats",
    "supply-chain",
    "insider-threats",
    "general",
]

_TOPLEVEL_NAMES = {
    "cyber-threats":   "Cyber Threats",
    "fraud":           "Fraud & Financial Crime",
    "ai-threats":      "AI Security Threats",
    "supply-chain":    "Supply Chain Compromise",
    "insider-threats": "Insider Threats",
    "general":         "General",
}

_SUBCAT_ORDER = ["apt", "ransomware", "vulnerability", "malware", "data-breach"]

_SUBCAT_NAMES = {
    "apt":           "Nation-State / APT",
    "ransomware":    "Ransomware",
    "vulnerability": "Vulnerabilities & Patches",
    "malware":       "Malware",
    "data-breach":   "Data Breaches",
}

# Inline styles — avoids dependency on <style> blocks that CKEditor strips.
_STYLE_CARD      = "border-left:3px solid #4472C4; padding-left:14px; margin-bottom:20px;"
_STYLE_ALSO_IN      = "color:#9ca3af; font-size:0.83em; font-style:italic; margin:0 0 6px 0;"
_STYLE_SUMMARY      = "color:#d1d5db; font-size:0.9em; margin:6px 0;"
_STYLE_SOURCES_HDR  = "color:#d1d5db; font-size:0.85em; margin:8px 0 4px 0;"
_STYLE_SOURCES_LI   = "color:#d1d5db; font-size:0.85em;"
_STYLE_SUBCAT_H  = "font-size:0.95em; color:#6b7280; text-transform:uppercase; letter-spacing:0.05em; margin:18px 0 8px 0;"
_STYLE_CNT_BADGE = "background:#e5e7eb; color:#374151; font-size:0.78em; padding:1px 6px; border-radius:9px; font-weight:normal; margin-left:6px;"

_BADGE_ACTOR   = "background:#fef3c7; color:#92400e; font-size:0.8em; padding:2px 7px; border-radius:4px; margin:2px 2px 2px 0; display:inline-block;"
_BADGE_MALWARE = "background:#fee2e2; color:#991b1b; font-size:0.8em; padding:2px 7px; border-radius:4px; margin:2px 2px 2px 0; display:inline-block;"
_BADGE_CVE     = "background:#fce7f3; color:#9d174d; font-size:0.8em; padding:2px 7px; border-radius:4px; margin:2px 2px 2px 0; display:inline-block;"
_BADGE_ORG     = "background:#e0f2fe; color:#0369a1; font-size:0.8em; padding:2px 7px; border-radius:4px; margin:2px 2px 2px 0; display:inline-block;"
_BADGE_PRODUCT = "background:#f3f4f6; color:#374151; font-size:0.8em; padding:2px 7px; border-radius:4px; margin:2px 2px 2px 0; display:inline-block;"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _fmt_domain(domain: str) -> str:
    return domain.removeprefix("www.")



def _entity_badges(cluster: "ClusterResult") -> str:
    """Inline-styled badge row for extracted entities."""
    fp = cluster.entity_fingerprint
    items: List[str] = []

    for actor in fp.threat_actors[:4]:
        items.append(f'<span style="{_BADGE_ACTOR}">{_esc(actor)}</span>')
    for mal in fp.malware[:3]:
        items.append(f'<span style="{_BADGE_MALWARE}">{_esc(mal)}</span>')
    for cve in fp.cves[:4]:
        items.append(f'<span style="{_BADGE_CVE}">{_esc(cve)}</span>')
    for org in fp.orgs[:3]:
        items.append(f'<span style="{_BADGE_ORG}">{_esc(org)}</span>')
    for prod in fp.products[:2]:
        items.append(f'<span style="{_BADGE_PRODUCT}">{_esc(prod)}</span>')

    if not items:
        return ""
    return "<p>" + " ".join(items) + "</p>"


def _platform_anchored_actors(result: "PipelineResult") -> List[str]:
    """Return threat actor names confirmed by the OpenCTI platform (confidence_tier='platform').

    Only platform-anchored entities are reliable enough to cite in the executive
    summary — NLI-verified-only names ("hackers", "Supply Chain Attackers") still
    pass role verification but are not validated against the knowledge base.
    """
    seen: set = set()
    actors: List[str] = []
    for cluster in result.clusters[:20]:
        for art in cluster.articles:
            for cand in art.entity_candidates:
                if (
                    cand.confidence_tier == "platform"
                    and cand.role == "threat_actor"
                    and cand.name.lower() not in seen
                ):
                    seen.add(cand.name.lower())
                    actors.append(cand.name)
    return actors


def _collect_candidate_names(cluster: "ClusterResult") -> List[str]:
    """Collect unique candidate-tier entity names from all articles in a cluster.

    These are entities GLiNER found but whose role NLI could not confirm with
    sufficient confidence (margin < 0.15) and that have no platform anchor.
    They appear as a plain-text footer — no badges, no STIX objects.
    """
    seen: set = set()
    names: List[str] = []
    for art in cluster.articles:
        for cand in art.entity_candidates:
            if cand.confidence_tier != "candidate":
                continue
            if cand.role in ("not_an_entity", "reporter"):
                continue
            key = cand.name.lower()
            if key not in seen:
                seen.add(key)
                names.append(cand.name)
    return names


# ---------------------------------------------------------------------------
# Cluster card rendering
# ---------------------------------------------------------------------------

def _render_article_line(article: "Article") -> str:
    domain = _fmt_domain(article.source_domain)
    pub = article.published.strftime("%b %-d")
    title = _esc(article.title[:100])
    url = article.link
    return f'{pub} — {title} — <a href="{url}">{_esc(domain)}</a>'


def _render_anchor_with_sources(cluster: "ClusterResult") -> str:
    """Render the anchor article line with all coverage sources as inline links.

    Format: "Apr 15 — Article Title — source1.com, source2.com, source3.com"

    The anchor is the earliest-published article; remaining sources are appended
    in publication order.  All per-article URLs are preserved so the analyst can
    read each outlet's framing directly.
    """
    articles = sorted(cluster.articles, key=lambda a: a.published)
    anchor = articles[0]
    pub = anchor.published.strftime("%b %-d")
    title = _esc(anchor.title[:100])

    source_links = [
        f'<a href="{art.link}">{_esc(_fmt_domain(art.source_domain))}</a>'
        for art in articles
    ]
    return f"{pub} — {title} — {', '.join(source_links)}"


def _render_sub_events(cluster: "ClusterResult") -> str:
    if not cluster.sub_events:
        return ""

    lines = ["<ul>"]
    for se in cluster.sub_events:
        victim = _esc(se.victim_org) if se.victim_org else "(general)"
        anchor_line = _render_article_line(se.anchor)
        lines.append(f"<li><strong>{victim}</strong> — {anchor_line}</li>")
    lines.append("</ul>")
    return "\n".join(lines)


def _render_cluster_card(
    cluster: "ClusterResult",
    current_section: str = "",
) -> str:
    """Render a single cluster as an HTML story card.

    current_section — the top-level SITREP section key in which this card is
    being rendered (e.g. "cyber-threats").  Used to build the cross-section
    "Also in:" badge that alerts analysts when the same cluster appears
    under multiple sections of the report.
    """
    parts: List[str] = [f'<div style="{_STYLE_CARD}">']

    # Title + source count badge
    title = _esc(cluster.title)
    article_count = len(cluster.articles)
    count_str = (
        f'<span style="{_STYLE_CNT_BADGE}">{article_count} sources</span>'
        if article_count > 1
        else ""
    )
    parts.append(f"<h3>{title}{count_str}</h3>")

    # Cross-section badge — shown whenever this cluster spans multiple SITREP
    # categories, listing every section OTHER than the one currently rendered.
    other_sections = [
        _TOPLEVEL_NAMES.get(c, c)
        for c in cluster.sitrep_categories
        if c != "general" and c != current_section
    ]
    if other_sections:
        cats = " · ".join(other_sections)
        parts.append(f'<p style="{_STYLE_ALSO_IN}">Also in: {_esc(cats)}</p>')

    # Anchor line: date — title — source1, source2, …
    # Sub-events path retained for migration-window compatibility; new clusterer
    # never populates sub_events.
    sub_html = _render_sub_events(cluster)
    if sub_html:
        parts.append(sub_html)
    else:
        parts.append(f"<p>{_render_anchor_with_sources(cluster)}</p>")

    # Extractive summary — no character truncation; the summariser is already
    # bounded by summary_max_sentences_extractive so mid-word cuts don't occur.
    if cluster.summary_extractive:
        parts.append(f'<p style="{_STYLE_SUMMARY}">{_esc(cluster.summary_extractive)}</p>')

    # Entity badges (verified / platform-anchored entities only)
    entity_html = _entity_badges(cluster)
    if entity_html:
        parts.append(entity_html)

    # Candidate footer — entities mentioned but whose role NLI could not confirm
    candidate_names = _collect_candidate_names(cluster)
    if candidate_names:
        names_str = ", ".join(_esc(n) for n in sorted(candidate_names))
        parts.append(
            '<p style="color:#9ca3af; font-size:0.8em; margin:4px 0;">'
            f'Mentioned but unconfirmed: {names_str}</p>'
        )

    parts.append("</div>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_cyber_threats_section(clusters: List["ClusterResult"]) -> str:
    """Render the Cyber Threats section with sub-category grouping."""
    parts: List[str] = []

    subcat_clusters: Dict[str, List["ClusterResult"]] = {k: [] for k in _SUBCAT_ORDER}
    other_clusters: List["ClusterResult"] = []

    for cluster in clusters:
        assigned = False
        for subcat in _SUBCAT_ORDER:
            if subcat in cluster.sitrep_cyber_subcats:
                subcat_clusters[subcat].append(cluster)
                assigned = True
        if not assigned:
            other_clusters.append(cluster)

    for subcat in _SUBCAT_ORDER:
        these = subcat_clusters[subcat]
        if not these:
            continue
        subcat_name = _SUBCAT_NAMES[subcat]
        parts.append(f'<h3 style="{_STYLE_SUBCAT_H}">{_esc(subcat_name)}</h3>')
        rendered_ids: Set[str] = set()
        for cluster in sorted(these, key=lambda c: len(c.articles), reverse=True):
            cid = cluster.cluster_id
            if cid in rendered_ids:
                continue
            rendered_ids.add(cid)
            parts.append(_render_cluster_card(cluster, current_section="cyber-threats"))

    if other_clusters:
        parts.append(f'<h3 style="{_STYLE_SUBCAT_H}">Other Cyber Threats</h3>')
        for cluster in sorted(
            other_clusters, key=lambda c: len(c.articles), reverse=True
        ):
            parts.append(_render_cluster_card(cluster, current_section="cyber-threats"))

    return "\n".join(parts)


def _render_generic_section(
    clusters: List["ClusterResult"], section_key: str = ""
) -> str:
    """Render a flat list of story cards for non-cyber sections."""
    parts: List[str] = []
    for cluster in sorted(clusters, key=lambda c: len(c.articles), reverse=True):
        parts.append(_render_cluster_card(cluster, current_section=section_key))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Executive summary (plain text — for Report description field only)
# ---------------------------------------------------------------------------

def _make_executive_summary(result: "PipelineResult") -> str:
    stats = result.stats
    total = stats.get("articles_relevant", 0)
    seen = stats.get("articles_seen", 0)
    filtered = stats.get("articles_filtered", 0)
    cluster_count = stats.get("clusters", 0)
    multi = cluster_count - stats.get("singleton_clusters", cluster_count)

    top_cves: List[str] = []
    for cluster in result.clusters[:20]:
        top_cves.extend(cluster.entity_fingerprint.cves[:2])

    cve_str = ""
    if top_cves:
        unique_cves = list(dict.fromkeys(top_cves))[:4]
        cve_str = f" Key CVEs: {', '.join(unique_cves)}."

    # Platform-anchored actors only — NLI-verified-only names are too noisy for the summary.
    plat_actors = _platform_anchored_actors(result)
    actor_str = ""
    if plat_actors:
        unique_actors = list(dict.fromkeys(plat_actors))[:4]
        actor_str = f" Notable threat actors: {', '.join(unique_actors)}."

    seen_str = f", {seen} already ingested" if seen else ""
    return (
        f"Processed {total} new articles from {len(result.config.get('feeds', []))} feeds "
        f"({filtered} filtered as non-TI{seen_str}). "
        f"Produced {cluster_count} stories ({multi} with multiple sources).{cve_str}{actor_str}"
    )


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------

_MAX_HTML_BYTES = 512 * 1024  # 512 KB — guards against STIX transport truncation


def generate_sitrep_html(result: "PipelineResult") -> str:
    """
    Generate the full SITREP HTML content for a PipelineResult.

    This is the text that goes into the OpenCTI Report's content tab.
    Uses only inline styles and standard HTML — no <style> block.
    The executive summary is intentionally omitted here; it lives in the
    Report's description field (displayed separately on the same page).
    """
    import logging as _logging
    _log = _logging.getLogger("sitrep")

    run_date = result.run_at.strftime("%Y-%m-%d")
    run_time = result.run_at.strftime("%H:%M UTC")

    header = (
        f"<h1>Daily SITREP — {run_date}</h1>\n"
        f'<p style="color:#9ca3af; font-size:0.85em;">Generated {run_time}</p>'
    )

    # Group clusters by top-level SITREP category.
    # A cluster with multiple categories appears under each applicable section.
    section_clusters: Dict[str, List["ClusterResult"]] = {k: [] for k in _TOPLEVEL_ORDER}
    for cluster in result.clusters:
        cats = cluster.sitrep_categories or ["general"]
        for cat in cats:
            if cat in section_clusters:
                section_clusters[cat].append(cluster)
        if not any(c in section_clusters for c in cats):
            section_clusters["general"].append(cluster)

    # Build sections in priority order; stop adding if the size cap would be exceeded.
    parts: List[str] = [header]
    total_bytes = len(header.encode())
    truncated = False

    for section_key in _TOPLEVEL_ORDER:
        clusters = section_clusters.get(section_key, [])
        if not clusters:
            continue

        section_name = _TOPLEVEL_NAMES.get(section_key, section_key.title())
        if section_key == "cyber-threats":
            section_html = (
                f"<h2>{_esc(section_name)}</h2>\n"
                + _render_cyber_threats_section(clusters)
            )
        else:
            section_html = (
                f"<h2>{_esc(section_name)}</h2>\n"
                + _render_generic_section(clusters, section_key=section_key)
            )

        section_bytes = len(section_html.encode())
        if total_bytes + section_bytes > _MAX_HTML_BYTES:
            truncated = True
            _log.warning(
                f"SITREP HTML approaching size limit ({total_bytes // 1024}KB used); "
                f"omitting section '{section_name}' and any remaining sections"
            )
            break

        parts.append(section_html)
        total_bytes += section_bytes

    if truncated:
        parts.append(
            '<p style="color:#6b7280; font-style:italic;">'
            "[Some sections omitted — SITREP exceeded the 512 KB size limit. "
            "Consider raising relevance_threshold or reducing max_age_days.]</p>"
        )

    # Sources block — outlet domains and article counts
    domain_counts: Dict[str, int] = {}
    for cluster in result.clusters:
        for art in cluster.articles:
            d = _fmt_domain(art.source_domain)
            domain_counts[d] = domain_counts.get(d, 0) + 1

    if domain_counts:
        sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1])
        source_lines = ", ".join(
            f"{_esc(d)} ({n})" for d, n in sorted_domains[:25]
        )
        parts.append(
            '<h2>Sources</h2>\n'
            f'<p style="color:#d1d5db; font-size:0.85em;">{source_lines}</p>'
        )

    return "\n".join(parts)


def generate_executive_summary(result: "PipelineResult") -> str:
    """
    Return a short plain-text executive summary for the Report description field.
    This is displayed separately from the HTML content tab.
    """
    return _make_executive_summary(result)
