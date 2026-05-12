# Flashpoint Connector — TODO

Items identified through code review and testing. Each item includes
the root cause, affected files, priority (P1–P3), and level of effort (S/M/L).

- **P1** = correctness or significant analyst-facing defect; fix before next release
- **P2** = analyst value improvement; fix in near-term
- **P3** = polish / operational visibility; fix when convenient

- **S** = < 1 hour, self-contained change
- **M** = 1–4 hours, touches 2–3 methods across files
- **L** = > 4 hours or requires design decisions

---

## ~~P1 — Fix report `published` date rendering off-by-one in non-UTC timezones~~ *(ON HOLD)*

**Root cause:** `build_daily_report()` sets `published` to midnight UTC of `date_str`
(`2026-04-09T00:00:00Z`). In any UTC− timezone, midnight UTC is the prior
calendar evening (e.g., UTC−4 renders it as April 8 at 8:00 PM). This makes
the published date appear to be one day earlier than the report title in the
OpenCTI UI.

**Observed behaviour:** Report titled `"Flashpoint Alerts — 2026-04-09"` shows a
published date of April 8, 2026 in the UI when viewed from a UTC−4 host.

**Fix:** Change `published` to noon UTC (`T12:00:00Z`) instead of midnight. Noon
UTC is the same calendar date in every real-world timezone (UTC−11 through UTC+12).

**File:** `src/flashpoint_connector/converter_to_stix.py` — `build_daily_report()`, line ~1561

**Priority:** P1 | **Effort:** S

---

## ~~P1 — Deduplicate STIX object IDs in daily batch Report `object_refs`~~ *(DONE)*

**Root cause:** `alert_to_report_objects()` and `convert_communities_result()` create
Channel/Persona SDOs with deterministic IDs via `Channel.generate_id()`. When
multiple alerts or results reference the same channel in one day, the same STIX ID
was appended to `bucket["objects"]` multiple times, producing a Report with duplicate
IDs in `object_refs` — technically invalid STIX 2.1.

**Fix applied:** Both `_import_alerts()` and `_import_communities()` flush sections
now deduplicate `bucket["objects"]` by `.id` (preserving first occurrence) via a
`seen` dict before passing to `build_daily_report()`.

**Priority:** P1 | **Effort:** S

---

## ~~P2 — Deduplicate external references on daily batch Reports~~ *(DONE)*

**Root cause:** Per-alert `flashpoint_url` values were appended to
`keyword_buckets[date_str]["ext_refs"]` unconditionally, producing duplicate
`stix2.ExternalReference` objects when two alerts shared the same URL.

**Fix applied:** Added `"seen_urls": set()` to each keyword bucket. The URL is
only appended if it has not already been added for that date.

**Priority:** P2 | **Effort:** S

---

## ~~P2 — Surface `alert_reason` (rule name) in batch Report path~~ *(DONE)*

**Fix applied:** `alert_to_report_objects()` now adds
`x_opencti_labels: ["rule:{alert_reason.lower()}"]` to the `CustomObservableText`
custom_properties, making each observable searchable and filterable by the alert
rule that produced it.

**Priority:** P2 | **Effort:** M

---

## P3 — Replace generic Report description with source-aware content

**Root cause:** All batch Reports (Alerts and Communities) receive the same static
description: `"Flashpoint intelligence batch for {date_str}. Automatically generated
by the Flashpoint connector."` This provides no context about source type or content
volume when a Report is viewed in isolation.

**Status:** Alert batch Reports now receive a count-based description
(`"N keyword-match alerts from Flashpoint Ignite for {date_str}."`) via the new
`description` param on `build_daily_report()`. Communities batch Reports still use
the generic fallback.

**Remaining fix:** Pass a source-aware description at the communities flush site, e.g.,
`"N posts from Flashpoint dark web communities for query '{query}' on {date_str}."`.

**Files:** `src/flashpoint_connector/connector.py` — `_import_communities()` flush;
`src/flashpoint_connector/converter_to_stix.py` — `build_daily_report()` (param
already exists).

**Priority:** P3 | **Effort:** S

---

## P3 — Include per-date alert counts in completion log and Report description

**Root cause:** The `[ALERTS] Complete` log line reports total IR count, total keyword
count, and skip count, but not how many daily batch Reports were emitted or how many
alerts each Report contains. This makes it hard to assess run volume at a glance.

**Status:** The Report `description` field now includes the alert count for each date
bucket. The completion log line does not yet show per-date breakdown.

**Remaining fix:** Add a `"count"` key to each `keyword_buckets` entry (or derive from
`len(bucket["alerts"])`). Log the number of Reports flushed and per-date counts in the
completion message.

**File:** `src/flashpoint_connector/connector.py` — `_import_alerts()`.

**Priority:** P3 | **Effort:** S

---

## ~~P2 — Use distinct `report_types` per dataset for lifecycle management~~ *(DONE)*

**Fix applied:**
- Finished intelligence reports (`convert_flashpoint_report()`) → `["activity-roundup"]`
- Keyword-match alert batch Reports → `["activity-roundup", "alerts-roundup"]`
- Communities batch Reports → `["activity-roundup"]`

`build_daily_report()` now accepts a `report_types` parameter (default `["activity-roundup"]`).
Both flush sites pass it explicitly.

`alerts-roundup` is registered alongside `activity-roundup` in
`_ensure_activity_roundup_vocabulary()` at connector startup.

With `alerts-roundup` as a dedicated type on alert batch Reports, a retention rule
scoped to `alerts-roundup` cleanly purges keyword-match noise without touching
finished intelligence or communities Reports, all of which share only
`activity-roundup`.

**Priority:** P2 | **Effort:** S

---

## ~~P2 — Add HTML analyst summary to batch alert Report Content field~~ *(DONE)*

**Fix applied:**
1. `"alerts": []` added to each `keyword_buckets` entry; raw processed alert dicts
   are accumulated alongside STIX objects.
2. New `build_alert_report_html(date_str, alerts, existing_content="")` static method
   in `converter_to_stix.py` generates HTML grouped by `alert_reason` with rule logic
   (`alert_logic`) shown as a `<pre><code>` block and a Time/Source/Channel/Author/
   Highlight/Link table per rule.
3. `build_daily_report()` accepts `description` and `content` params; `content` is
   written to `x_opencti_content`.
4. Flush site reads existing Report content before building the new section (see #13).

**Priority:** P2 | **Effort:** M

---

## ~~P2 — Smart truncation for `highlight_text` using `<mark>` context window~~ *(DONE)*

**Fix applied:** New `_excerpt_highlight(text, context=60)` module-level helper in
`converter_to_stix.py`. Uses sentinel characters to map `<mark>` positions into the
stripped plain text, builds ±60-char context windows around each match, merges
overlapping windows, and joins non-adjacent windows with ` … `.

Called from `alert_to_report_objects()` (observable `value`) and
`build_alert_report_html()` (Highlight table cell).

**Priority:** P2 | **Effort:** S

---

## ~~P2 — Fix `CustomObservableText` value: use excerpt, full text in description~~ *(DONE)*

**Fix applied:** In `alert_to_report_objects()`:
- `value` = `_excerpt_highlight(highlight_text)` (~120 chars centred on `<mark>` spans)
- `x_opencti_description` = provenance header + full `highlight_text`

**Priority:** P2 | **Effort:** S

---

## P3 — Investigate media embedding via HTML `<img>` in `x_opencti_content`

**Background:** The alert batch Report Content field is generated HTML. CKEditor
(used by OpenCTI's Content editor) supports embedded images via base64 data URIs:
`<img src="data:image/jpeg;base64,...">`. The connector already fetches media
binary content and MIME type for media-source alerts (stored in
`processed["media_content"]` and `processed["media_type"]`).

**If OpenCTI renders data URIs in `x_opencti_content`:** the media image can be
embedded directly in the HTML summary table, eliminating the need for the
`x_opencti_files` attachment mechanism for the summary use case.

**Investigation needed:**
1. Confirm OpenCTI's content renderer allows data URI `<img>` tags (not stripped
   by a sanitizer).
2. Confirm size limits — large images as base64 in the STIX bundle may hit
   OpenCTI worker message size limits.

**Current state:** media alerts show `[media attachment]` in the highlight cell.
Keep this as the fallback if data URI embedding is not feasible.

**Priority:** P3 | **Effort:** M (investigation + implementation if feasible)

---

## P3 — Communities batch Report HTML summary (grouped by channel)

**Background:** The alert batch Report HTML summary (#8) is now implemented and
validated. Apply the same pattern to communities batch Reports.

**Design difference from alerts:** Communities Reports are already one-per-query-term,
so there is no rule-name grouping. Within the Report, content would be grouped by
channel (`channel_name` / `channel_type`) as `<h2>` headings, with posts as table
rows: Time | Channel | Author | Excerpt | Link.

**Priority:** P3 | **Effort:** M

---

## ~~P2 — HTML summary content strategy: per-run section headers (append model)~~ *(DONE)*

**Fix applied:** At flush time, the connector reads the existing Report's
`x_opencti_content` via `helper.api.report.read(id=report_stix_id)` (the STIX ID
is deterministic from name + published date). `build_alert_report_html()` accepts
`existing_content` and prepends the new run's section above it, separated by `<hr>`.
If no prior content exists, the new section becomes the full content — no special
handling needed.

**Priority:** P2 | **Effort:** M

---

## P3 — AI first-pass triage of keyword-match alerts

**Concept:** Use the Flashpoint alert rule name, rule logic (`alert_logic`), and the
alert `highlight_text` to ask an LLM whether the matched content actually fits the
*intent* of the rule. Many alerts match the rule's keyword logic but are obvious false
positives when the content is read (e.g., a job posting matching a
credential-exposure rule). An AI triage verdict in the HTML summary reduces analyst
time-to-decision on each alert.

**Prerequisite complete:** `alert_logic` is now extracted in `_process_alert()` (#15).

**Triage prompt structure:**
```
Rule name: {alert_reason}
Rule logic: {alert_logic}
Alert content: {highlight_text}

Does this content match the intent of the rule?
Reply: LIKELY_TP, LIKELY_FP, or UNCLEAR
One sentence of reasoning.
```

**Output integration:**
- Add a "Triage" column to the HTML summary table: verdict badge + reasoning tooltip
- Optionally apply verdict as a label on the Text observable for filtering in OpenCTI

**Model recommendation:** Use a fast, low-cost model (e.g., claude-haiku-4-5) to keep
per-alert cost minimal. Triage is a first-pass signal, not a final determination.

**Concerns to resolve before implementing:**
1. **Cost:** API call per alert; high-volume days could be expensive. Consider a
   per-run budget cap or only triaging alerts above a minimum highlight length.
2. **Rate limiting:** Batch runs making many sequential AI calls may hit API rate
   limits. Needs retry-with-backoff or batching.
3. **Latency:** Each AI call adds latency to the connector run. Acceptable for
   PT6H intervals; may need async handling for very high alert volumes.
4. **Configuration:** AI API key and model should be configurable via env vars /
   config.yml, with triage disabled by default (opt-in).

**Files (when implementing):**
- `src/flashpoint_connector/config_variables.py` — new config vars: AI API key,
  model, enable toggle, max calls per run
- `src/flashpoint_connector/converter_to_stix.py` — `build_alert_report_html()`
  consumes triage results per alert
- `src/flashpoint_connector/connector.py` — triage called during alert processing
  before bucket accumulation

**Priority:** P3 | **Effort:** L

---

## ~~P2 — Extract `alert["reason"]["text"]` as `alert_logic` in `_process_alert()`~~ *(DONE)*

**Fix applied:** Added to `_process_alert()` processed dict:
```python
"alert_logic": (alert.get("reason") or {}).get("text") or "",
```

**Use sites implemented:**
- `build_alert_report_html()`: displays rule logic as a `<pre><code>` block under
  each `<h3>` rule heading in the HTML Content tab
- `_build_alert_markdown()`: adds a **Rule Logic** fenced code block to the IR
  alert.md attachment when `alert_logic` is present

**Priority:** P2 | **Effort:** S

---

## P2 — Implement Compromised Credentials dataset

**Status:** Blocked on API documentation. Three stub methods are fully scaffolded
and ready to implement once the API contract is confirmed.

**Stubs that need implementation:**
- `src/flashpoint_connector/client_api.py` — `get_credentials()`, line ~370
- `src/flashpoint_connector/connector.py` — `_import_credentials()`, line ~1051
- `src/flashpoint_connector/converter_to_stix.py` — `convert_credential_record()`, line ~1548

**Step 1 — Confirm the API contract from `docs.flashpoint.io`**

All of the following must be confirmed before any code can be written:

*Endpoint and transport:*
- Endpoint path (e.g. `/compromised-credentials/v1/...` or `/cti/v1/credentials/...`)
- HTTP method (GET vs POST)
- Authentication: same `Authorization: Bearer` header or different scheme
- Whether CCMC group membership is required on the API key (README notes this requirement — confirm it applies to this endpoint)

*Date filtering:*
- Parameter name for the start-date filter (e.g. `created_after`, `since`, `start_date`)
- Expected format (ISO8601, Unix epoch, or other)
- Whether the filter applies to discovery date, exposure date, or ingestion date — matters for cursor design

*Pagination:*
- Style: offset/limit (like `/finished-intelligence/v1/reports`), cursor token (like `/alert-management/v1/notifications`), or page integer (like `/sources/v2/communities`)
- Response field carrying the next-page token or total count

*Response schema — these fields drive all three implementation sites:*

| Purpose | Field name(s) to confirm |
|---|---|
| Record unique ID | e.g. `id`, `_id`, `record_id` — needed for deterministic STIX ID generation |
| Exposed username / email | e.g. `username`, `email`, `credential` — becomes the User-Account observable `user_id` / `account_login` |
| Domain of the exposed credential | e.g. `domain`, `email_domain`, extracted from email — drives org-domain bifurcation against `FLASHPOINT_ORG_DOMAINS` |
| Source type / breach category | e.g. `source_type`, `breach_type` (`stealer_log`, `forum_post`, `marketplace`) — becomes Incident label and description |
| Discovery / first-seen timestamp | e.g. `created_at`, `discovered_at`, `first_seen` — used as Incident `created`, drives cursor advancement |
| Source URL (breach location) | e.g. `source_url`, `url` — becomes URL Observable if present |
| Flashpoint platform URL | e.g. `flashpoint_url`, `platform_url` — ExternalReference + URL Observable linking back to Ignite |
| Password (if exposed) | e.g. `password` — **do not store as an observable value**; include only as a flag (`password_exposed: true`) in Incident description or label |

**Step 2 — Implement `client_api.get_credentials(start_date)`**

Pattern to follow: `get_alerts()` for cursor pagination or `get_reports()` for offset pagination.
The method must:
- Accept `start_date: str` (ISO8601)
- Page through all results and return a flat `list[dict]`
- Raise `FlashpointAPIError` (or let `requests` propagate) on HTTP errors — same pattern as other methods
- Log `[CREDENTIALS] Fetched N records since {start_date}` at info level

**Step 3 — Implement `connector._import_credentials()`**

Pattern to follow: `_import_alerts()` (bifurcation + daily batch bucket logic).

```
1. Read credentials_last_run cursor (same pattern as other datasets)
2. records = self.client.get_credentials(start_date)
3. For each record:
     domain = record[<domain_field>]
     if any(d in domain for d in self.config.org_domains):
         # Org match → IR path
         objects = self.converter.convert_credential_record(record, is_org=True)
         ir_name = f"Flashpoint Credential Exposure — {record[<id_field>]}"
         self.helper.api.case_incident.create(...)
         send bundle
     else:
         # Non-org → accumulate in daily bucket keyed by discovery date
         date_str = record[<timestamp_field>][:10]
         cred_buckets[date_str]["objects"].extend(objects)
4. Flush non-org buckets as daily batch Reports
     name = f"Flashpoint Compromised Credentials — {date_str}"
     report_types = ["observed-data"]  (same as alerts/communities)
5. Advance credentials_last_run cursor to now_iso
```

Log pattern to emit at completion:
`[CREDENTIALS] Complete — IR: X, batch: Y, skipped: Z`

**Step 4 — Implement `converter_to_stix.convert_credential_record(record, is_org)`**

Pattern to follow: `credential_alert_to_incident_objects()` (same file, line ~1089) for the IR path.

Objects to create per record:

| Object | Type | Condition |
|---|---|---|
| `stix2.Incident` | SDO | `is_org=True` only |
| `stix2.UserAccount` | SCO | Always — `user_id` = exposed username or email |
| `stix2.DomainName` | SCO | Always — `value` = domain of exposed credential |
| `stix2.URL` | SCO | If source URL present in record |
| `stix2.URL` | SCO | If Flashpoint platform URL present in record |
| `related-to` relationships | SRO | Each SCO → Incident (IR path) or → Flashpoint author identity (non-org floor) |

Deterministic ID: `stix2.Incident.id = Incident.generate_id(name=ir_name, created=record[<timestamp>])`

**Note on password field:** If the API returns a password value, do **not** create an observable for it. Include a label `password-exposed` on the Incident/Report member and note it in the description. Storing cleartext passwords as observable values creates data-handling risk and violates the instance data model.

**Files:**
- `src/flashpoint_connector/client_api.py` — `get_credentials()`
- `src/flashpoint_connector/connector.py` — `_import_credentials()`
- `src/flashpoint_connector/converter_to_stix.py` — `convert_credential_record()`

**Priority:** P2 | **Effort:** L (API documentation lookup is Step 1; implementation is M once schema is confirmed)

---

## Summary

| # | Description | Priority | Effort | Status |
|---|-------------|----------|--------|--------|
| 1 | ~~Report `published` date off-by-one in UTC− timezones~~ *(ON HOLD)* | P1 | S | On hold |
| 2 | ~~Duplicate STIX IDs in batch Report `object_refs`~~ | P1 | S | Done |
| 3 | ~~Duplicate external references on batch Reports~~ | P2 | S | Done |
| 4 | ~~`alert_reason` label on Text observable~~ | P2 | M | Done |
| 5 | Generic Report description (communities path remaining) | P3 | S | Partial |
| 6 | Per-date alert count in completion log | P3 | S | Partial |
| 7 | ~~Use distinct `report_types` per dataset for retention scoping~~ | P2 | S | Done |
| 8 | ~~Add HTML analyst summary to batch alert Report Content field~~ | P2 | M | Done |
| 9 | ~~Smart truncation for `highlight_text` using `<mark>` context window~~ | P2 | S | Done |
| 10 | ~~Fix `CustomObservableText` value: excerpt as value, full text in description~~ | P2 | S | Done |
| 11 | Investigate media embedding via HTML `<img>` in `x_opencti_content` | P3 | M | Open |
| 12 | Communities batch Report HTML summary (grouped by channel) | P3 | M | Open |
| 13 | ~~HTML summary content strategy: per-run section headers (append model)~~ | P2 | M | Done |
| 14 | AI first-pass triage of keyword-match alerts | P3 | L | Open |
| 15 | ~~Extract `alert["reason"]["text"]` as `alert_logic` in `_process_alert()`~~ | P2 | S | Done |
| 16 | Implement Compromised Credentials dataset (blocked on API docs) | P2 | L | Blocked |
