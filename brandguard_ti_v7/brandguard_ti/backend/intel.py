from __future__ import annotations

import copy
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import requests

try:
    from ipwhois import IPWhois  # type: ignore
except Exception:  # pragma: no cover
    IPWhois = None

URLHAUS_TEXT_FEED = "https://urlhaus.abuse.ch/downloads/text/"
CRT_SH_JSON = "https://crt.sh/?q={query}&output=json"
RDAP_DOMAIN = "https://rdap.org/domain/{domain}"
REQUEST_HEADERS = {"User-Agent": "BrandGuardDemo/4.1"}


@dataclass
class PublicIntelResult:
    urlhaus_hit: bool = False
    urlhaus_evidence: list[str] | None = None
    crtsh_hits: int = 0
    crtsh_subjects: list[str] | None = None
    crtsh_names: list[str] | None = None
    rdap_asn: str | None = None
    rdap_asn_description: str | None = None
    rdap_country: str | None = None
    rdap_network: str | None = None
    ip: str | None = None
    host: str | None = None
    provider_hint: str | None = None
    registrar: str | None = None
    name_servers: list[str] | None = None
    domain_created: str | None = None
    domain_last_changed: str | None = None
    domain_expires: str | None = None
    domain_age_days: int | None = None
    privacy_proxy: bool = False
    recently_created: bool = False
    recently_updated: bool = False
    ownership_churn_indicator: str = "unknown"
    timeline_notes: list[str] | None = None
    intel_score: int = 0
    intel_level: str = "unknown"
    notes: list[str] | None = None


def _registrable_domain(hostname: str | None) -> str | None:
    if not hostname:
        return None
    host = hostname.lower().strip('.')
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    common_second_level = {"co", "com", "net", "org", "gov", "ac", "edu"}
    if parts[-2] in common_second_level and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    try:
        text = str(value).replace('Z', '+00:00')
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except Exception:
        return None


@lru_cache(maxsize=1)
def _urlhaus_feed_text() -> str:
    resp = requests.get(URLHAUS_TEXT_FEED, timeout=12, headers=REQUEST_HEADERS)
    resp.raise_for_status()
    return resp.text


@lru_cache(maxsize=256)
def _crtsh_lookup(query: str) -> list[dict[str, Any]]:
    url = CRT_SH_JSON.format(query=requests.utils.quote(query, safe=""))
    resp = requests.get(url, timeout=8, headers=REQUEST_HEADERS)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


@lru_cache(maxsize=1024)
def _resolve_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


@lru_cache(maxsize=1024)
def _rdap_lookup(ip: str) -> dict[str, Any] | None:
    if IPWhois is None:
        return None
    try:
        return IPWhois(ip).lookup_rdap(depth=1)
    except Exception:
        return None


@lru_cache(maxsize=512)
def _rdap_domain_lookup(domain: str) -> dict[str, Any] | None:
    if not domain:
        return None
    try:
        resp = requests.get(RDAP_DOMAIN.format(domain=domain), timeout=10, headers=REQUEST_HEADERS)
        if resp.status_code >= 400:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _extract_name(obj: dict[str, Any]) -> str | None:
    vcard = obj.get('vcardArray')
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == 'fn':
                value = item[3]
                if value:
                    return str(value).strip()
    for key in ('handle', 'name'):
        value = obj.get(key)
        if value:
            return str(value).strip()
    return None


class PublicIntelEnricher:
    """Free, no-key enrichment sources suitable for a fast demo."""

    def __init__(self) -> None:
        self._cache: dict[str, PublicIntelResult] = {}

    def lookup(self, url: str) -> PublicIntelResult:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return PublicIntelResult(host=None, notes=["No hostname available for enrichment."])

        cache_key = host.lower()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return copy.deepcopy(cached)

        result = PublicIntelResult(host=host, notes=[], timeline_notes=[], name_servers=[])
        reg_domain = _registrable_domain(host)

        ip = _resolve_ip(host)
        if ip:
            result.ip = ip
            rdap = _rdap_lookup(ip)
            if rdap:
                result.rdap_asn = rdap.get('asn')
                result.rdap_asn_description = rdap.get('asn_description')
                network = rdap.get('network') or {}
                result.rdap_country = network.get('country')
                result.rdap_network = network.get('name') or network.get('handle')
                result.provider_hint = result.rdap_asn_description or result.rdap_network
                if result.rdap_asn_description:
                    result.notes.append(f"Provider/ASN: {result.rdap_asn_description}.")
                elif result.rdap_network:
                    result.notes.append(f"Network: {result.rdap_network}.")
            result.notes.append(f"Resolved IP: {ip}.")

        domain_rdap = _rdap_domain_lookup(reg_domain or host)
        if domain_rdap:
            events = domain_rdap.get('events') or []
            created = None
            last_changed = None
            expires = None
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = str(event.get('eventAction') or '').lower()
                dt = _parse_dt(event.get('eventDate'))
                if dt is None:
                    continue
                if action in {'registration', 'registered', 'created'} and created is None:
                    created = dt
                elif action in {'last changed', 'changed', 'update'} and last_changed is None:
                    last_changed = dt
                elif action in {'expiration', 'expiry', 'expires'} and expires is None:
                    expires = dt

            if created:
                result.domain_created = created.isoformat()
                result.domain_age_days = max(0, (datetime.now(timezone.utc) - created).days)
                result.timeline_notes.append(f"Created {result.domain_age_days} day(s) ago.")
                result.recently_created = result.domain_age_days <= 90
            if last_changed:
                result.domain_last_changed = last_changed.isoformat()
                days_since_change = max(0, (datetime.now(timezone.utc) - last_changed).days)
                result.recently_updated = days_since_change <= 90
                result.timeline_notes.append(f"Last changed {days_since_change} day(s) ago.")
            if expires:
                result.domain_expires = expires.isoformat()
                result.timeline_notes.append(f"Expires on {expires.date().isoformat()}.")

            nameservers = []
            for ns in domain_rdap.get('nameservers') or []:
                if isinstance(ns, dict):
                    value = ns.get('ldhName') or ns.get('unicodeName')
                    if value:
                        nameservers.append(str(value).strip())
            result.name_servers = list(dict.fromkeys(nameservers))[:6]

            registrar = None
            privacy_proxy = False
            for entity in domain_rdap.get('entities') or []:
                if not isinstance(entity, dict):
                    continue
                roles = [str(role).lower() for role in (entity.get('roles') or [])]
                name = _extract_name(entity)
                remarks = ' '.join(str(r.get('description') or '') for r in (entity.get('remarks') or []) if isinstance(r, dict))
                if 'registrar' in roles and name and registrar is None:
                    registrar = name
                if 'registrant' in roles:
                    if not name or any(k in (remarks + ' ' + name).lower() for k in ('privacy', 'redacted', 'proxy', 'whoisguard', 'guard')):
                        privacy_proxy = True
            result.registrar = registrar
            result.privacy_proxy = privacy_proxy or not bool(result.name_servers)
            if result.registrar:
                result.notes.append(f"Registrar: {result.registrar}.")
            if result.name_servers:
                result.notes.append(f"Nameservers: {', '.join(result.name_servers[:3])}.")
            if result.privacy_proxy:
                result.notes.append("Registrant data looks privacy-protected or redacted.")

            if result.domain_age_days is not None:
                if result.domain_age_days <= 14:
                    result.ownership_churn_indicator = 'high'
                elif result.domain_age_days <= 30:
                    result.ownership_churn_indicator = 'high' if (result.recently_updated or result.privacy_proxy) else 'medium'
                elif result.domain_age_days <= 90:
                    result.ownership_churn_indicator = 'high' if (result.recently_updated and result.privacy_proxy) else 'medium'
                elif result.recently_updated or result.privacy_proxy:
                    result.ownership_churn_indicator = 'medium'
                else:
                    result.ownership_churn_indicator = 'low'
            elif result.recently_updated or result.privacy_proxy:
                result.ownership_churn_indicator = 'medium'

            if result.domain_age_days is not None and result.domain_age_days <= 30:
                result.timeline_notes.append('Very young domain: common in throwaway phishing infrastructure.')
            if result.recently_updated and result.domain_age_days is not None and result.domain_age_days <= 90:
                result.timeline_notes.append('Recently updated registration data adds churn risk.')
            if result.privacy_proxy:
                result.timeline_notes.append('Ownership details are hidden, which reduces transparency.')
            if result.ownership_churn_indicator == 'high':
                result.timeline_notes.append('The registration timeline suggests frequent change or resale risk.')
            elif result.ownership_churn_indicator == 'medium':
                result.timeline_notes.append('The domain shows some churn indicators, so review is recommended.')

        # Run the remaining enrichment lookups in parallel so the demo feels faster.
        from concurrent.futures import ThreadPoolExecutor

        def _urlhaus_worker() -> tuple[bool, list[str] | None]:
            try:
                text = _urlhaus_feed_text().lower()
            except Exception as exc:
                result.notes.append(f"URLhaus unavailable: {exc.__class__.__name__}.")
                return False, None

            hits: list[str] = []
            for needle in filter(None, [url.strip().lower(), host.lower(), reg_domain.lower() if reg_domain else None]):
                if needle in text:
                    hits.append(needle)
            return bool(hits), sorted(set(hits)) if hits else None

        def _crtsh_worker() -> tuple[int, list[str] | None, list[str] | None]:
            queries = []
            if reg_domain:
                queries.append(f"%.{reg_domain}")
            queries.append(host)

            subjects: list[str] = []
            names: list[str] = []
            hits = 0
            for q in queries:
                try:
                    items = _crtsh_lookup(q)
                except Exception:
                    continue
                hits += len(items)
                for item in items[:20]:
                    cn = (item.get('common_name') or '').strip()
                    name_value = (item.get('name_value') or '').strip()
                    if cn:
                        subjects.append(cn)
                    if name_value:
                        names.extend([x.strip() for x in name_value.split('\n') if x.strip()])
            return hits, list(dict.fromkeys(subjects))[:10], list(dict.fromkeys(names))[:25]

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_urlhaus = pool.submit(_urlhaus_worker)
            fut_crtsh = pool.submit(_crtsh_worker)
            urlhaus_hit, urlhaus_evidence = fut_urlhaus.result()
            crtsh_hits, crtsh_subjects, crtsh_names = fut_crtsh.result()

        result.urlhaus_hit = urlhaus_hit
        result.urlhaus_evidence = urlhaus_evidence
        result.crtsh_hits = crtsh_hits
        result.crtsh_subjects = crtsh_subjects
        result.crtsh_names = crtsh_names

        if result.urlhaus_hit:
            result.notes.append('Matched the public URLhaus malicious URL corpus.')
        if result.crtsh_hits:
            result.notes.append('Certificate Transparency records were found for this host or domain.')
        if result.provider_hint:
            result.notes.append(f'Observed hosting/provider hint: {result.provider_hint}.')

        self._apply_scoring(result)
        self._cache[cache_key] = copy.deepcopy(result)
        return result

    def _apply_scoring(self, result: PublicIntelResult) -> None:
        score = 0
        if result.urlhaus_hit:
            score += 70
        if result.crtsh_hits:
            score += 10
        if result.rdap_asn_description:
            score += 4
        if result.ip:
            score += 3
        if result.domain_age_days is not None:
            if result.domain_age_days <= 14:
                score += 35
            elif result.domain_age_days <= 30:
                score += 28
            elif result.domain_age_days <= 90:
                score += 16
            elif result.domain_age_days <= 180:
                score += 8
        if result.recently_updated:
            score += 6
        if result.privacy_proxy:
            score += 5
        if result.ownership_churn_indicator == 'high':
            score += 8
        elif result.ownership_churn_indicator == 'medium':
            score += 6
        result.intel_score = max(0, min(score, 100))
        if result.intel_score >= 75:
            result.intel_level = 'high'
        elif result.intel_score >= 35:
            result.intel_level = 'medium'
        elif result.intel_score > 0:
            result.intel_level = 'low'
        else:
            result.intel_level = 'none'
        if not result.notes:
            result.notes = ['No strong public threat-intel indicators were found.']

    def to_dict(self, result: PublicIntelResult) -> dict[str, Any]:
        return asdict(result)
