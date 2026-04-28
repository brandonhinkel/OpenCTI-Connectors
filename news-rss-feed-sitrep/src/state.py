"""
state.py — Connector state management.

Wraps pycti's helper.get_state() / helper.set_state() to track which article
URLs have already been ingested.  This prevents re-pushing expensive NLP output
on subsequent runs within the same day and provides the foundation for future
cross-run cluster linking.
"""

import logging
from typing import Set

logger = logging.getLogger("state")

_URLS_KEY = "ingested_article_urls"
_MAX_URLS = 100_000  # cap to prevent unbounded state growth


class ConnectorState:
    """Manages persistent connector state across runs."""

    def __init__(self, helper):
        self.helper = helper
        raw = helper.get_state() or {}
        self._ingested: Set[str] = set(raw.get(_URLS_KEY, []))
        logger.debug(f"State loaded: {len(self._ingested)} previously ingested URLs")

    def is_new(self, url: str) -> bool:
        """Return True if this URL has not been ingested before."""
        return url not in self._ingested

    def mark_ingested(self, url: str) -> None:
        """Record a URL as ingested."""
        self._ingested.add(url)

    def mark_ingested_batch(self, urls) -> None:
        """Record multiple URLs as ingested."""
        self._ingested.update(urls)

    @property
    def ingested_urls(self) -> Set[str]:
        """The set of all previously ingested article URLs."""
        return self._ingested

    def __len__(self) -> int:
        """Return total number of tracked URLs."""
        return len(self._ingested)

    def new_article_count(self, urls) -> int:
        """Count how many of these URLs are new (not previously ingested)."""
        return sum(1 for u in urls if u not in self._ingested)

    def save(self) -> None:
        """Persist current state back to OpenCTI."""
        urls = list(self._ingested)
        # Prune to cap to avoid unbounded state growth.
        # No ordering guarantee — just keep the most-recently-added end of the list.
        if len(urls) > _MAX_URLS:
            urls = urls[-_MAX_URLS:]
            logger.debug(f"State pruned to {_MAX_URLS} URLs")
        self.helper.set_state({_URLS_KEY: urls})
        logger.debug(f"State saved: {len(urls)} ingested URLs")
