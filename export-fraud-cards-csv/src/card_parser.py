"""
Card data extraction from unstructured text (Telegram fraud channel messages).

Handles two primary formats:
  1. Pipe-delimited:  CARD|MM|YYYY|CVV  or  CARD|MM/YY|CVV
  2. Key-value:       CC: CARD\\nEXP: MM/YY\\nCVV: NNN

Falls back to raw Luhn-validated card number extraction if neither format matches.

A text may produce multiple CardData records (bulk dump messages often contain
many cards, one per line in pipe-delimited format).
"""
import re
from dataclasses import dataclass, field


@dataclass
class CardData:
    card_number: str            # digits only, no spaces or dashes
    expiration_month: str = ""  # zero-padded, e.g. "06"
    expiration_year: str = ""   # 4-digit, e.g. "2025"
    cvv: str = ""
    cardholder_name: str = ""


# ── Luhn validation ───────────────────────────────────────────────────────────

def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in reversed(number)]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Normalisation helpers ─────────────────────────────────────────────────────

def _clean(raw: str) -> str:
    """Strip spaces and dashes from a raw card number string."""
    return re.sub(r"[\s\-]", "", raw)


def _valid_card(raw: str) -> str | None:
    """Return the cleaned card number if it passes basic validity checks, else None."""
    cleaned = _clean(raw)
    if 13 <= len(cleaned) <= 19 and cleaned.isdigit() and _luhn_check(cleaned):
        return cleaned
    return None


def _pad_month(mm: str) -> str:
    return mm.zfill(2)


def _normalize_year(yy: str) -> str:
    return ("20" + yy) if len(yy) == 2 else yy


# ── Pipe-delimited patterns ───────────────────────────────────────────────────
#
# Format A (4 fields):  CARD|MM|YY[YY]|CVV[|NAME]
# Format B (3 fields):  CARD|MM[/-]YY[YY]|CVV[|NAME]
#
# Card number: leading digit, 11-20 middle chars (digits/spaces/dashes),
# trailing digit → total 13-22 chars, 13-19 actual digits after cleaning.

_CARD_FRAG = r"(\d[\d \-]{11,20}\d)"
_NAME_FRAG = r"(?:\|([^|\n\r]{1,50}))?"   # optional 5th field

_PIPE_A = re.compile(
    _CARD_FRAG
    + r"\|(\d{1,2})\|(\d{2,4})\|(\d{3,4})"
    + _NAME_FRAG
)

_PIPE_B = re.compile(
    _CARD_FRAG
    + r"\|(\d{1,2})[/\-](\d{2,4})\|(\d{3,4})"
    + _NAME_FRAG
)


def _parse_pipe(text: str) -> list[CardData]:
    results: list[CardData] = []
    seen: set[str] = set()

    for pattern in (_PIPE_A, _PIPE_B):
        for m in pattern.finditer(text):
            g = m.groups()
            card_raw, mm, yy, cvv = g[0], g[1], g[2], g[3]
            name = (g[4] or "").strip()

            card = _valid_card(card_raw)
            if not card or card in seen:
                continue
            seen.add(card)
            results.append(CardData(
                card_number=card,
                expiration_month=_pad_month(mm),
                expiration_year=_normalize_year(yy),
                cvv=cvv,
                cardholder_name=name,
            ))

    return results


# ── Key-value patterns ────────────────────────────────────────────────────────

_CC_RE = re.compile(
    r"(?:CC|CREDIT\s*CARD|CARD(?:\s*(?:NUMBER|NO|NUM|#))?|PAN|NUMBER|NUM|CN)"
    r"\s*[:=]\s*"
    r"(\d[\d \-]{11,20}\d)",
    re.IGNORECASE,
)

# Expiry: MM/YY, MM-YY, MM YY, MM.YY — with optional 4-digit year
_EXP_RE = re.compile(
    r"(?:EXP(?:IRY|IRATION)?(?:\s*DATE)?|VALID(?:\s*(?:THRU|THROUGH|UNTIL))?|DATE|VALIDITY)"
    r"\s*[:=]\s*"
    r"(\d{1,2})[/\-\.\s](\d{2,4})",
    re.IGNORECASE,
)

# Fallback for bare MMYY / MMYYYY after expiry key
_EXP_BARE_RE = re.compile(
    r"(?:EXP(?:IRY|IRATION)?(?:\s*DATE)?|VALID(?:\s*(?:THRU|THROUGH|UNTIL))?|DATE|VALIDITY)"
    r"\s*[:=]\s*"
    r"(\d{4,6})\b",
    re.IGNORECASE,
)

_CVV_RE = re.compile(
    r"(?:CVV2?|CVC2?|CSC|SECURITY\s*CODE|SEC(?:URITY)?)"
    r"\s*[:=]\s*(\d{3,4})",
    re.IGNORECASE,
)

_NAME_RE = re.compile(
    r"(?:NAME|HOLDER|CARDHOLDER|CARD\s*HOLDER|OWNER|CLIENT|CUSTOMER)"
    r"\s*[:=]\s*([A-Za-z][A-Za-z \-\'\.]{1,49})",
    re.IGNORECASE,
)


def _extract_exp(text: str) -> tuple[str, str]:
    """Return (month, year) strings or ('', '') if not found."""
    m = _EXP_RE.search(text)
    if m:
        return _pad_month(m.group(1)), _normalize_year(m.group(2))
    m = _EXP_BARE_RE.search(text)
    if m:
        digits = m.group(1)
        if len(digits) == 4:             # MMYY
            return _pad_month(digits[:2]), _normalize_year(digits[2:])
        if len(digits) == 6:             # MMYYYY
            return _pad_month(digits[:2]), digits[2:]
    return "", ""


def _parse_kv(text: str) -> list[CardData]:
    results: list[CardData] = []
    seen: set[str] = set()

    for m in _CC_RE.finditer(text):
        card = _valid_card(m.group(1))
        if not card or card in seen:
            continue
        seen.add(card)

        # For each card number found, search the surrounding block (±400 chars)
        # for the other fields. This keeps multi-card KV messages from cross-contaminating.
        start = max(0, m.start() - 400)
        end = min(len(text), m.end() + 400)
        block = text[start:end]

        mm, yy = _extract_exp(block)
        cvv_m = _CVV_RE.search(block)
        name_m = _NAME_RE.search(block)

        results.append(CardData(
            card_number=card,
            expiration_month=mm,
            expiration_year=yy,
            cvv=cvv_m.group(1) if cvv_m else "",
            cardholder_name=name_m.group(1).strip() if name_m else "",
        ))

    return results


# ── Raw card number fallback ──────────────────────────────────────────────────

# Finds any digit sequence that could be a card number (13-19 actual digits,
# optionally grouped with spaces or dashes). Luhn validation filters noise.
_RAW_CARD_RE = re.compile(r"\b(\d[\d \-]{11,20}\d)\b")


def _parse_raw(text: str) -> list[CardData]:
    results: list[CardData] = []
    seen: set[str] = set()
    for m in _RAW_CARD_RE.finditer(text):
        card = _valid_card(m.group(1))
        if card and card not in seen:
            seen.add(card)
            results.append(CardData(card_number=card))
    return results


# ── Public API ────────────────────────────────────────────────────────────────

def parse_cards(text: str) -> list[CardData]:
    """Extract all card records from a text string.

    Returns a list of CardData objects. Each item is guaranteed to have a
    Luhn-valid card_number. A single text may yield multiple records when the
    message is a bulk dump (one card per line in pipe-delimited format).

    Strategy (in order):
      1. Pipe-delimited patterns — handles bulk dumps.
      2. Key-value patterns — handles single-card labelled messages.
      3. Raw card number extraction — last-resort fallback.
    """
    results = _parse_pipe(text)
    if not results:
        results = _parse_kv(text)
    if not results:
        results = _parse_raw(text)
    return results
