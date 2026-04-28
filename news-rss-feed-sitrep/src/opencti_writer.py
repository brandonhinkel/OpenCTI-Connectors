"""
opencti_writer.py — STIX bundle creation and OpenCTI ingest.

Responsibilities:
  1. Resolve existing OpenCTI entities (IntrusionSet, Malware, Vulnerability)
     before creating any new objects.
  2. Create news outlet Organization identities (one per source domain).
  3. Build x-opencti-text observables for each article (deduplicated by URL).
  4. Build relationships:
       - observable → intelligence entities (related-to)
       - observable → outlet Organization (related-to)          [anchoring]
       - IntrusionSet → Malware (uses)                          [entity-to-entity]
  5. Build the daily SITREP Report referencing all objects.
  6. Push everything as a single STIX 2.1 bundle via helper.send_stix2_bundle().

All STIX IDs are generated using pycti's generate_id() utilities, which apply
stix2 canonical JSON serialization before hashing — ensuring our IDs match what
the OpenCTI platform would derive server-side for the same objects.

Bundle objects are constructed as Python dicts so that custom types
(x-opencti-text) and extended Report fields (x_opencti_content) can be
included without fighting the stix2 library's schema validation.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

from pycti import (
    Identity as PyCTIIdentity,
    IntrusionSet as PyCTIIntrusionSet,
    Malware as PyCTIMalware,
    Report as PyCTIReport,
    StixCoreRelationship,
    Vulnerability as PyCTIVulnerability,
)
from stix2 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE

if TYPE_CHECKING:
    from pipeline import Article, ClusterResult, PipelineResult
    from state import ConnectorState

logger = logging.getLogger("opencti_writer")

_TLP_ID_MAP = {
    "WHITE": TLP_WHITE.id,
    "GREEN": TLP_GREEN.id,
    "AMBER": TLP_AMBER.id,
    "RED":   TLP_RED.id,
}

# OpenCTI namespace — used for IDs of custom/connector-specific objects that
# have no pycti generate_id counterpart (x-opencti-text observables, bundles).
_OPENCTI_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


# ---------------------------------------------------------------------------
# ID generators
# ---------------------------------------------------------------------------

def _observable_id(article_url: str) -> str:
    """Deterministic ID for a Text observable, keyed on the article URL.

    Uses the article URL rather than the title so that two articles with the
    same headline but different URLs remain separate observables.  This is a
    connector-level convention; the ID won't match OpenCTI's server-side
    value-based dedup, but since we control creation with update=True, the
    result is consistent.

    NOTE: Must use the "text--" prefix. The STIX bundle splitter checks the
    type prefix against STIX_CYBER_OBSERVABLE_MAPPING, which maps "text" →
    "Text". The legacy "x-opencti-text" prefix is not in that mapping and
    causes the splitter to silently drop all observable objects.
    """
    return f"text--{uuid.uuid5(_OPENCTI_NS, article_url)}"


def _sitrep_report_id(report_name: str, published_iso: str) -> str:
    """pycti-compatible deterministic ID for the SITREP Report."""
    return PyCTIReport.generate_id(report_name, published_iso)


def _relationship_id(
    rel_type: str, source_ref: str, target_ref: str
) -> str:
    """pycti-compatible deterministic ID for a relationship (no time window)."""
    return StixCoreRelationship.generate_id(rel_type, source_ref, target_ref)


# ---------------------------------------------------------------------------
# STIX dict builders
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _make_text_observable(
    article: "Article",
    summary: str,
    sitrep_labels: List[str],
    author_id: str,
    tlp_id: str,
    confidence: int,
) -> dict:
    """Build an x-opencti-text observable dict for a news article."""
    now = _now_iso()
    published = article.published.isoformat().replace("+00:00", "Z")
    domain = article.source_domain.removeprefix("www.")
    pub_date = article.published.strftime("%Y-%m-%d")

    obj: dict = {
        "type": "text",
        "spec_version": "2.1",
        "id": _observable_id(article.link),
        "value": article.title[:512],
        "created": published,
        "modified": now,
        "created_by_ref": author_id,
        "object_marking_refs": [tlp_id],
        "labels": sitrep_labels,
        "external_references": [
            {
                "source_name": domain,
                "url": article.link,
                "description": f"Published: {pub_date}",
            }
        ],
        "x_opencti_description": (
            summary[:2000] if summary else article.description[:500]
        ),
        "x_opencti_score": confidence,
    }

    return obj


def _make_relationship_dict(
    rel_type: str,
    from_id: str,
    to_id: str,
    author_id: str,
    tlp_id: str,
) -> dict:
    now = _now_iso()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _relationship_id(rel_type, from_id, to_id),
        "relationship_type": rel_type,
        "source_ref": from_id,
        "target_ref": to_id,
        "created": now,
        "modified": now,
        "created_by_ref": author_id,
        "object_marking_refs": [tlp_id],
    }



# ---------------------------------------------------------------------------
# Actor alias table (Phase 6.2)
# ---------------------------------------------------------------------------

def build_actor_alias_table(helper) -> Dict[str, str]:
    """Build {lowercase_alias → canonical_name} from all OpenCTI IntrusionSets.

    Called once at connector startup.  The MITRE ATT&CK connector (standard in
    most deployments) imports ATT&CK Groups with their full alias lists, so this
    single query returns both the MITRE dataset and any operator-curated aliases —
    no external ATT&CK STIX fetch required (design v3.3 decision #3).

    Returns an empty dict on failure so the pipeline degrades gracefully (actor
    names pass through un-canonicalized rather than crashing the run).
    """
    alias_table: Dict[str, str] = {}
    try:
        entities = helper.api.intrusion_set.list(getAll=True)
        if not entities:
            return alias_table
        for node in entities:
            if isinstance(node, dict) and "node" in node:
                node = node["node"]
            canonical = (node.get("name") or "").strip()
            if not canonical:
                continue
            alias_table[canonical.lower()] = canonical
            for alias in (node.get("aliases") or []):
                if alias and alias.strip():
                    alias_table[alias.strip().lower()] = canonical
        logger.info(
            f"Actor alias table: {len(alias_table)} entries "
            f"from {len(entities)} IntrusionSets"
        )
    except Exception as exc:
        logger.warning(
            f"Could not build actor alias table: {exc}; "
            "actor canonicalization disabled for this run"
        )
    return alias_table


# ---------------------------------------------------------------------------
# Entity resolver
# ---------------------------------------------------------------------------

class EntityResolver:
    """
    Queries OpenCTI for existing entities by name.

    Results are cached within a single run to avoid redundant round-trips.
    Only returns IDs for entities already in the platform — no new entities
    are created from NER output.
    """

    def __init__(self, helper):
        self.helper = helper
        # Maps cache_key → (stix_id, is_platform_known)
        self._cache: Dict[str, Tuple[str, bool]] = {}

    def _make_filter(self, key: str, value: str) -> dict:
        return {
            "mode": "and",
            "filters": [{"key": key, "values": [value], "operator": "eq"}],
            "filterGroups": [],
        }

    def resolve_intrusion_set(self, name: str) -> Tuple[str, bool]:
        """Returns (stix_id, platform_known)."""
        cache_key = f"is:{name.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = None
        try:
            result = self.helper.api.intrusion_set.read(
                filters=self._make_filter("name", name)
            )
        except Exception as exc:
            logger.debug(f"IntrusionSet lookup failed for '{name}': {exc}")

        if result:
            stix_id = result.get("standard_id") or result.get("id", "")
            entry: Tuple[str, bool] = (stix_id, True)
        else:
            entry = (PyCTIIntrusionSet.generate_id(name), False)

        self._cache[cache_key] = entry
        return entry

    def resolve_malware(self, name: str) -> Tuple[str, bool]:
        cache_key = f"mw:{name.lower()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = None
        try:
            result = self.helper.api.malware.read(
                filters=self._make_filter("name", name)
            )
        except Exception as exc:
            logger.debug(f"Malware lookup failed for '{name}': {exc}")

        if result:
            stix_id = result.get("standard_id") or result.get("id", "")
            entry = (stix_id, True)
        else:
            entry = (PyCTIMalware.generate_id(name), False)

        self._cache[cache_key] = entry
        return entry

    def resolve_vulnerability(self, cve_id: str) -> Tuple[str, bool]:
        cache_key = f"vuln:{cve_id.upper()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = None
        try:
            result = self.helper.api.vulnerability.read(
                filters=self._make_filter("name", cve_id.upper())
            )
        except Exception as exc:
            logger.debug(f"Vulnerability lookup failed for '{cve_id}': {exc}")

        if result:
            stix_id = result.get("standard_id") or result.get("id", "")
            entry = (stix_id, True)
        else:
            entry = (PyCTIVulnerability.generate_id(cve_id), False)

        self._cache[cache_key] = entry
        return entry

    def lookup_type_for_name(self, name: str) -> Optional[Tuple[str, str]]:
        """
        Check whether a candidate entity name is known to OpenCTI.

        Queries IntrusionSet and Malware — the two entity types most frequently
        mislabelled by GLiNER.  Returns (role, stix_id) where role is
        'threat_actor' or 'malware', or None if the platform has no record.

        Results are backed by the existing resolve_* caches so repeated calls
        within a run are free.
        """
        stix_id, known = self.resolve_intrusion_set(name)
        if known:
            return ("threat_actor", stix_id)
        stix_id, known = self.resolve_malware(name)
        if known:
            return ("malware", stix_id)
        return None


# ---------------------------------------------------------------------------
# Main writer class
# ---------------------------------------------------------------------------

class OpenCTIWriter:
    """Builds and pushes STIX bundles to OpenCTI from pipeline output."""

    _author_id_cache: Optional[str] = None  # cached for the connector process lifetime

    def __init__(self, helper, config: dict):
        self.helper = helper
        self.config = config

        tlp_str = config.get("tlp", "WHITE").upper()
        self.tlp_id: str = _TLP_ID_MAP.get(tlp_str, TLP_WHITE.id)
        self.confidence: int = int(config.get("confidence", 50))

        if OpenCTIWriter._author_id_cache is None:
            OpenCTIWriter._author_id_cache = self._ensure_author()
        self.author_id: str = OpenCTIWriter._author_id_cache
        self.resolver = EntityResolver(helper)

    # ------------------------------------------------------------------
    # Author identity
    # ------------------------------------------------------------------

    def _ensure_author(self) -> str:
        """Get or create the connector's Identity. Returns the STIX ID."""
        author_name = "RSS SITREP Connector"
        stix_id = PyCTIIdentity.generate_id(author_name, "organization")
        try:
            result = self.helper.api.identity.create(
                type="Organization",
                name=author_name,
                description=(
                    "Automated daily threat intelligence SITREP connector. "
                    "Objects created by this identity are news-sourced and unverified."
                ),
                stix_id=stix_id,
                update=True,
            )
            return result.get("standard_id") or stix_id
        except Exception as exc:
            logger.warning(f"Could not create/retrieve author identity: {exc}")
            return stix_id

    # ------------------------------------------------------------------
    # Per-cluster entity resolution
    # ------------------------------------------------------------------

    def _resolve_cluster_entities(
        self,
        cluster: "ClusterResult",
        bundle_ids: Set[str],
    ) -> Dict[str, str]:
        """
        Resolve the entities in a cluster fingerprint against OpenCTI.

        Only entities that already exist in the platform are returned.
        New entities are never created — NER output from news articles is
        too noisy to reliably populate the knowledge base automatically.
        An analyst can add missing entities manually if needed.

        Returns:
            entity_ids — maps entity key → platform STIX ID (known entities only)
        """
        fp = cluster.entity_fingerprint
        entity_ids: Dict[str, str] = {}

        for actor in fp.threat_actors[:8]:
            stix_id, known = self.resolver.resolve_intrusion_set(actor)
            if known:
                entity_ids[f"actor:{actor}"] = stix_id

        for malware in fp.malware[:8]:
            stix_id, known = self.resolver.resolve_malware(malware)
            if known:
                entity_ids[f"malware:{malware}"] = stix_id

        for cve in fp.cves[:10]:
            stix_id, known = self.resolver.resolve_vulnerability(cve)
            if known:
                entity_ids[f"vuln:{cve}"] = stix_id

        return entity_ids

    # ------------------------------------------------------------------
    # Entity-to-entity relationships within a cluster
    # ------------------------------------------------------------------

    def _build_entity_relationships(
        self,
        entity_ids: Dict[str, str],
        bundle_ids: Set[str],
    ) -> List[dict]:
        """
        Create semantically grounded entity-to-entity relationships.

        IntrusionSet → uses → Malware  when both appear in the same cluster.
        Both sides must be resolved (existing or new in this bundle) before the
        relationship is created; we never create dangling references.
        """
        rel_objects: List[dict] = []

        actor_ids = [v for k, v in entity_ids.items() if k.startswith("actor:")]
        malware_ids = [v for k, v in entity_ids.items() if k.startswith("malware:")]

        for actor_id in actor_ids:
            for malware_id in malware_ids:
                rel_id = _relationship_id("uses", actor_id, malware_id)
                if rel_id not in bundle_ids:
                    rel_objects.append(
                        _make_relationship_dict(
                            "uses", actor_id, malware_id,
                            self.author_id, self.tlp_id,
                        )
                    )
                    bundle_ids.add(rel_id)

        return rel_objects

    # ------------------------------------------------------------------
    # Platform anchor lookup (Phase 6.1)
    # ------------------------------------------------------------------

    def anchor_candidates(self, result: "PipelineResult") -> None:
        """
        Upgrade 'candidate' tier entities that can be confirmed by OpenCTI.

        For every article in the pipeline result, queries the platform for each
        entity candidate that NLI left as 'candidate' confidence (ambiguous role).
        A platform hit is authoritative: the candidate's role is corrected and its
        tier promoted to 'platform'.

        After updating candidates, rebuilds each article's EntityFingerprint and
        the enclosing ClusterResult's entity_fingerprint so that subsequent SITREP
        HTML generation and STIX bundle construction use the most accurate data.

        Must be called BEFORE generate_sitrep_html() so the cluster card badges
        and candidate footer reflect platform-confirmed roles.
        """
        from pipeline import EntityFingerprint

        def _merge(arts) -> "EntityFingerprint":
            return EntityFingerprint(
                cves=sorted({c for a in arts for c in a.entities.cves}),
                techniques=sorted({t for a in arts for t in a.entities.techniques}),
                threat_actors=sorted({x for a in arts for x in a.entities.threat_actors}),
                malware=sorted({m for a in arts for m in a.entities.malware}),
                orgs=sorted({o for a in arts for o in a.entities.orgs}),
                products=sorted({p for a in arts for p in a.entities.products}),
            )

        for cluster in result.clusters:
            cluster_changed = False
            for article in cluster.articles:
                art_changed = False
                for cand in article.entity_candidates:
                    if cand.confidence_tier != "candidate":
                        continue
                    platform_info = self.resolver.lookup_type_for_name(cand.name)
                    if platform_info is None:
                        continue
                    platform_role, _stix_id = platform_info
                    cand.role = platform_role
                    cand.confidence_tier = "platform"
                    cand.score = 1.0
                    art_changed = True

                if art_changed:
                    # Rebuild article fingerprint from updated candidates
                    threat_actors, malware_list, orgs, products = [], [], [], []
                    for cand in article.entity_candidates:
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
                    article.entities.threat_actors = sorted(set(threat_actors))
                    article.entities.malware = sorted(set(malware_list))
                    article.entities.orgs = sorted(set(orgs))
                    article.entities.products = sorted(set(products))
                    cluster_changed = True

            if cluster_changed:
                cluster.entity_fingerprint = _merge(cluster.articles)

    # ------------------------------------------------------------------
    # SITREP write orchestration
    # ------------------------------------------------------------------

    def write_sitrep(
        self,
        result: "PipelineResult",
        sitrep_html: str,
        exec_summary: str,
        work_id: Optional[str],
        state: "ConnectorState",
    ) -> None:
        """
        Build and push the STIX bundle for the pipeline result.

        Bundle contents per run:
          - N x-opencti-text observables (one per new article)
          - Relationships: observable → intel entity (related-to, platform-known only)
          - Relationships: intrusion-set → malware (uses, co-occurring in same cluster)
          - 1 SITREP Report (daily container, updated in place on re-runs via update=True)

        Source domain attribution is recorded in each observable's external_references
        rather than as a separate Organization identity + relationship. This keeps the
        relationship graph bounded and avoids cluttering the entity list.
        """
        if not result.clusters:
            logger.warning("Pipeline produced no clusters; skipping bundle push")
            return

        sitrep_date = result.run_at.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        date_str = sitrep_date.strftime("%Y-%m-%d")
        report_name = f"SITREP — {date_str}"
        published_iso = sitrep_date.isoformat().replace("+00:00", "Z")

        logger.info(
            f"Building STIX bundle for {report_name} — "
            f"{len(result.clusters)} clusters"
        )

        bundle_objects: List[dict] = []
        bundle_ids: Set[str] = set()
        all_object_refs: Set[str] = set()
        new_url_batch: List[str] = []

        # --- Process each cluster ---
        for cluster in result.clusters:
            entity_ids = self._resolve_cluster_entities(cluster, bundle_ids)
            all_object_refs.update(entity_ids.values())

            entity_rels = self._build_entity_relationships(entity_ids, bundle_ids)
            bundle_objects.extend(entity_rels)

            cluster_summary = cluster.summary_extractive or ""

            for article in cluster.articles:
                obs_id = _observable_id(article.link)

                sitrep_labels = sorted(
                    set(article.sitrep_categories + cluster.sitrep_categories)
                    - {"general"}
                ) or ["general"]

                if obs_id not in bundle_ids:
                    bundle_objects.append(
                        _make_text_observable(
                            article=article,
                            summary=cluster_summary,
                            sitrep_labels=sitrep_labels,
                            author_id=self.author_id,
                            tlp_id=self.tlp_id,
                            confidence=self.confidence,
                        )
                    )
                    bundle_ids.add(obs_id)

                all_object_refs.add(obs_id)
                new_url_batch.append(article.link)

                # Relationships: observable → platform-known intelligence entities
                for entity_id in entity_ids.values():
                    rel_id = _relationship_id("related-to", obs_id, entity_id)
                    if rel_id not in bundle_ids:
                        bundle_objects.append(
                            _make_relationship_dict(
                                "related-to", obs_id, entity_id,
                                self.author_id, self.tlp_id,
                            )
                        )
                        bundle_ids.add(rel_id)

        # --- Build SITREP Report ---
        report_id = _sitrep_report_id(report_name, published_iso)

        report_dict: dict = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "name": report_name,
            "report_types": ["threat-report"],
            "published": published_iso,
            "description": exec_summary,
            "created": published_iso,
            "modified": _now_iso(),
            "created_by_ref": self.author_id,
            "object_marking_refs": [self.tlp_id],
            "labels": ["daily-sitrep"],
            "object_refs": (
                sorted(all_object_refs) if all_object_refs else [self.author_id]
            ),
            "confidence": self.confidence,
            "x_opencti_report_status": 0,  # "New"
            "x_opencti_content": sitrep_html,
        }
        bundle_objects.append(report_dict)

        # --- Push bundle ---
        logger.info(
            f"Pushing bundle: {len(bundle_objects)} objects "
            f"({len(all_object_refs)} Report object_refs)"
        )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": bundle_objects,
        }

        try:
            self.helper.send_stix2_bundle(
                json.dumps(bundle, default=str),
                update=True,
                work_id=work_id,
            )
            logger.info(f"Bundle pushed successfully for {report_name}")
        except Exception as exc:
            logger.error(f"Bundle push failed: {exc}")
            raise

        # --- Update state ---
        state.mark_ingested_batch(new_url_batch)
        logger.info(f"Marked {len(new_url_batch)} article URLs as ingested in state")
