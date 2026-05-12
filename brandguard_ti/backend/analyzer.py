from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from backend.intel import PublicIntelEnricher

BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

SUSPICIOUS_KEYWORDS = {
    "login", "sign in", "signin", "verify", "verification", "secure", "security",
    "password", "account", "update", "confirm", "authenticate", "otp", "two-factor",
    "2fa", "mfa", "unlock", "suspended", "expired", "re-enter", "recover", "reset",
    "appointment", "passport", "visa", "booking", "checkout", "payment", "session",
}

COMMON_SLD_SUFFIXES = {"co", "com", "net", "org", "gov", "ac", "edu"}

DEFAULT_WEIGHTS = {
    "password_with_offdomain": 22,
    "password_on_legit_domain": 0,
    "off_domain_form_action": 32,
    "brand_text_match": 6,
    "logo_match": 24,
    "domain_mismatch": 18,
    "suspicious_brand_keywords": 5,
    "hidden_inputs_present": 4,
    "http_page": 3,
    "iframe_present": 3,
    "obfuscated_js": 7,
    "brand_in_title": 5,
    "urlhaus_hit": 55,
    "recent_domain": 28,
    "updated_domain": 8,
    "privacy_proxy": 6,
    "ownership_churn": 8,
}

def _normalize_slug(value: str | None) -> str:
    if not value:
        return ""
    text = unicodedata.normalize("NFKD", value)
    text = text.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def _brand_terms(value: str | None) -> list[str]:
    if not value:
        return []
    slug = _normalize_slug(value)
    words = [w for w in re.findall(r"[a-z0-9]+", value.lower()) if len(w) > 2]
    tokens = list(dict.fromkeys(words + ([slug] if slug else [])))
    return tokens[:8]


def _safe_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_json(v) for v in obj]
    if isinstance(obj, tuple):
        return [_safe_json(v) for v in obj]
    return obj


def _simple_phash(image: Image.Image, hash_size: int = 8) -> int:
    """Return a compact perceptual hash for coarse logo similarity."""
    try:
        img = image.convert("L").resize((hash_size, hash_size), Image.Resampling.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / max(1, len(pixels))
        bits = 0
        for pixel in pixels:
            bits = (bits << 1) | int(pixel >= avg)
        return bits
    except Exception:
        return 0


def _hamming_distance(a: int, b: int) -> int:
    return int((a ^ b).bit_count())


def _load_image_from_bytes(blob: bytes) -> Image.Image | None:
    try:
        from io import BytesIO
        img = Image.open(BytesIO(blob))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        return img
    except Exception:
        return None


def _load_image_from_path(path: Path) -> Image.Image | None:
    try:
        if not path.exists():
            return None
        return _load_image_from_bytes(path.read_bytes())
    except Exception:
        return None


def _crop_candidates(img: Image.Image) -> list[Image.Image]:
    """Generate likely logo-bearing crops from a screenshot."""
    try:
        w, h = img.size
        if w < 32 or h < 32:
            return [img]
        crops: list[Image.Image] = [img]
        top_h = max(96, int(h * 0.28))
        left_w = max(128, int(w * 0.40))
        center_w = max(160, int(w * 0.50))
        right_w = max(128, int(w * 0.40))

        crops.extend([
            img.crop((0, 0, w, top_h)),
            img.crop((0, 0, left_w, top_h)),
            img.crop((max(0, (w - center_w) // 2), 0, min(w, (w + center_w) // 2), top_h)),
            img.crop((max(0, w - right_w), 0, w, top_h)),
            img.crop((0, 0, max(1, int(w * 0.30)), max(1, int(h * 0.22)))),
        ])
        unique: list[Image.Image] = []
        seen = set()
        for crop in crops:
            key = crop.size
            if key not in seen:
                seen.add(key)
                unique.append(crop)
        return unique
    except Exception:
        return [img]


def _logo_similarity_score(ref: Image.Image, candidate: Image.Image) -> tuple[int, int]:
    """Return (distance, normalized confidence) using a light-weight hash."""
    try:
        ref_hash = _simple_phash(ref)
        cand_hash = _simple_phash(candidate)
        dist = _hamming_distance(ref_hash, cand_hash)
        confidence = max(0, min(100, int(round((1 - dist / 64.0) * 100))))
        return dist, confidence
    except Exception:
        return 64, 0


def _image_data_url(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
        return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    except Exception:
        return None


def _make_placeholder_screenshot(path: Path, url: str, title: str, note: str) -> None:
    img = Image.new("RGB", (1440, 900), color=(9, 14, 28))
    draw = ImageDraw.Draw(img)
    font_big = ImageFont.load_default()
    font_small = ImageFont.load_default()
    draw.rounded_rectangle((36, 36, 1404, 864), radius=26, outline=(92, 128, 210), width=2)
    draw.text((74, 82), "BrandGuard capture", fill=(246, 249, 255), font=font_big)
    draw.text((74, 150), f"URL: {url}", fill=(190, 210, 255), font=font_small)
    draw.text((74, 220), f"Title: {title or 'n/a'}", fill=(190, 210, 255), font=font_small)
    draw.text((74, 290), f"Note: {note}", fill=(190, 210, 255), font=font_small)
    draw.text((74, 374), "Screenshot fallback used because the live browser page could not be captured.", fill=(160, 167, 180), font=font_small)
    img.save(path)


CAPTCHA_PHRASES = (
    "verify you are human",
    "security check",
    "attention required",
    "just a moment",
    "cloudflare",
    "captcha",
    "turnstile",
    "hcaptcha",
    "recaptcha",
    "challenge",
)


def _captcha_hint(html: str, title: str, url: str) -> dict[str, Any]:
    raw = f"{title}\n{html}\n{url}".lower()
    patterns = (
        "verify you are human",
        "security check",
        "attention required",
        "just a moment",
        "cloudflare",
        "captcha",
        "turnstile",
        "hcaptcha",
        "recaptcha",
        "challenge",
        "cf-chl",
        "cf-challenge",
    )
    hints = [phrase for phrase in patterns if phrase in raw]
    if not hints:
        return {"detected": False, "reason": None, "keywords": []}
    reason = f"challenge indicator(s): {', '.join(hints[:4])}"
    return {
        "detected": True,
        "reason": reason,
        "keywords": hints[:8],
    }
@dataclass
class AnalysisInput:
    url: str
    brand_name: str = ""
    official_domain: str = ""
    max_images: int = 5
    timeout_ms: int = 12000


class BrandGuardAnalyzer:
    """Passive webpage analyst with conservative phishing and brand-abuse scoring."""

    def __init__(self, weights: dict[str, int] | None = None) -> None:
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.intel = PublicIntelEnricher()
        self._logo_cache: dict[str, int] = {}

    def analyze(
        self,
        target: AnalysisInput,
        reference_logos: list[bytes] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, Any]:
        def update(pct: int, message: str) -> None:
            if progress:
                try:
                    progress(int(max(0, min(100, pct))), message)
                except Exception:
                    pass

        update(3, "Starting browser capture")
        capture = self._capture_page(target.url, target.timeout_ms)
        update(22, "Extracting page evidence")
        parsed = self._extract_features(capture["html"], capture["final_url"], target.max_images)
        captcha_detected = bool(capture.get("captcha_detected"))
        captcha_reason = capture.get("captcha_reason")

        update(42, "Checking brand and logo signals")
        logo_match = False
        logo_details: list[dict[str, Any]] = []
        if reference_logos:
            logo_match, logo_details = self._match_logos(
                reference_logos,
                parsed["image_urls"],
                capture.get("screenshot_path"),
                parsed.get("favicon_urls", []),
            )

        update(58, "Collecting public threat intelligence")
        public_intel = self.intel.lookup(capture["final_url"])
        infrastructure = self._build_infrastructure(capture["final_url"], public_intel)

        update(72, "Calculating phishing and trademark score")
        signals = self._collect_signals(
            parsed=parsed,
            final_url=capture["final_url"],
            page_title=capture["title"],
            brand_name=target.brand_name,
            official_domain=target.official_domain,
            logo_match=logo_match,
            infra=infrastructure,
            redirects=capture["redirects"],
            public_intel=public_intel,
            captcha_detected=captcha_detected,
        )
        overall_score, reasons = self._score_signals(signals, public_intel)
        category_scores = self._category_scores(signals, public_intel)
        insight_cards = self._insight_cards(signals, public_intel, target, reasons)

        update(90, "Packaging analyst output")
        result = {
            "target": {
                "input_url": target.url,
                "final_url": capture["final_url"],
                "brand_name": target.brand_name or None,
                "official_domain": target.official_domain or None,
            },
            "risk_score": overall_score,
            "verdict": self._verdict(overall_score),
            "summary": self._summary(signals, reasons, target.brand_name, target.official_domain, public_intel),
            "reasons": reasons,
            "category_scores": category_scores,
            "insight_cards": insight_cards,
            "signals": {
                **signals,
                "logo_matches": logo_details,
            },
            "threat_intel": self.intel.to_dict(public_intel),
            "infrastructure": infrastructure,
            "access": {
                "captcha_detected": captcha_detected,
                "captcha_solved": False,
                "captcha_reason": captcha_reason,
                "captcha_supported": False,
                "analysis_limited": bool(captcha_detected),
            },
            "evidence": {
                "title": capture["title"],
                "forms": parsed["forms"],
                "links_count": len(parsed["links"]),
                "scripts_count": len(parsed["scripts"]),
                "image_urls": parsed["image_urls"],
                "meta": parsed["meta"],
                "redirects": capture["redirects"],
                "screenshot": capture["screenshot_path"],
                "screenshot_data_url": capture.get("screenshot_data_url"),
                "captcha_detected": captcha_detected,
            },
            "extensibility": {
                "architecture": "modular detectors + public threat intel enrichment + conservative scoring + challenge detection",
                "upgrade_path": [
                    "load 50+ brand profiles from JSON",
                    "add logo embeddings and OCR later",
                    "swap in more intel feeds without changing the UI",
                ],
            },
        }
        update(100, "Done")
        return _safe_json(result)


    def _capture_page(self, url: str, timeout_ms: int) -> dict[str, Any]:
        shot_name = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()[:12] + ".png"
        screenshot_path = OUTPUT_DIR / shot_name
        html = ""
        final_url = url
        title = ""
        redirects: list[str] = []
        capture_note = "browser capture"

        parsed = urlparse(url)
        if parsed.scheme == "file":
            try:
                html = Path(parsed.path).read_text(encoding="utf-8", errors="ignore")
                title = self._extract_title(html)
                captcha = _captcha_hint(html, title, url)
                _make_placeholder_screenshot(screenshot_path, url, title, "local file capture")
                return {
                    "html": html,
                    "final_url": url,
                    "title": title,
                    "redirects": redirects,
                    "screenshot_path": f"outputs/{screenshot_path.name}",
                    "screenshot_data_url": _image_data_url(screenshot_path),
                    "captcha_detected": captcha["detected"],
                    "captcha_reason": captcha["reason"],
                    "captcha_keywords": captcha["keywords"],
                }
            except Exception:
                pass

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(viewport={"width": 1440, "height": 1600}, ignore_https_errors=True)
                page = context.new_page()
                page.set_default_timeout(max(3500, min(timeout_ms, 10000)))
                page.route(
                    "**/*",
                    lambda route: route.abort()
                    if route.request.resource_type in {"font", "media", "websocket"}
                    else route.continue_(),
                )
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=max(4500, min(timeout_ms, 10000)))
                    if response:
                        try:
                            redirects = [r.url for r in response.request.redirected_from_chain]  # type: ignore[attr-defined]
                        except Exception:
                            redirects = []
                    page.wait_for_timeout(350)
                except PlaywrightTimeoutError:
                    capture_note = "browser timeout"
                except Exception as exc:
                    capture_note = f"browser error: {exc.__class__.__name__}"

                try:
                    html = page.content()
                except Exception:
                    html = ""
                try:
                    final_url = page.url or url
                except Exception:
                    final_url = url
                try:
                    title = page.title() or ""
                except Exception:
                    title = ""

                captcha = _captcha_hint(html, title, final_url)
                if captcha["detected"]:
                    capture_note = captcha.get("reason") or "captcha/challenge detected"
                    try:
                        page.wait_for_timeout(1200)
                        html_retry = page.content()
                        title_retry = page.title() or title
                        captcha_retry = _captcha_hint(html_retry, title_retry, final_url)
                        if not captcha_retry["detected"]:
                            html = html_retry
                            title = title_retry
                            capture_note = "challenge cleared during retry"
                            captcha = captcha_retry
                    except Exception:
                        pass

                try:
                    page.screenshot(path=str(screenshot_path), full_page=True)
                except Exception:
                    try:
                        page.locator("body").screenshot(path=str(screenshot_path))
                    except Exception:
                        _make_placeholder_screenshot(screenshot_path, final_url, title, capture_note)
                browser.close()
        except Exception as exc:
            capture_note = f"playwright unavailable: {exc.__class__.__name__}"
            try:
                resp = __import__("requests").get(url, timeout=8, headers={"User-Agent": "BrandGuardDemo/4.0"})
                html = resp.text
                final_url = resp.url
                title = self._extract_title(html)
            except Exception:
                html = ""
                final_url = url
                title = ""
            _make_placeholder_screenshot(screenshot_path, final_url, title, capture_note)

        if not html:
            html = ""
        if not title:
            title = self._extract_title(html)
        if not screenshot_path.exists():
            _make_placeholder_screenshot(screenshot_path, final_url, title, capture_note)

        data_url = _image_data_url(screenshot_path)
        if not data_url:
            _make_placeholder_screenshot(screenshot_path, final_url, title, "screenshot fallback")
            data_url = _image_data_url(screenshot_path)

        captcha = _captcha_hint(html, title, final_url)

        return {
            "html": html,
            "final_url": final_url,
            "title": title,
            "redirects": redirects,
            "screenshot_path": f"outputs/{screenshot_path.name}",
            "screenshot_data_url": data_url,
            "captcha_detected": captcha["detected"],
            "captcha_reason": captcha["reason"],
            "captcha_keywords": captcha["keywords"],
        }

    def _extract_features(self, html: str, base_url: str, max_images: int) -> dict[str, Any]:
        soup = BeautifulSoup(html or "", "lxml")
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        title = self._extract_title(html)
        meta = {tag.get("name", "").lower(): tag.get("content", "") for tag in soup.find_all("meta") if tag.get("name")}

        forms: list[dict[str, Any]] = []
        for form in soup.find_all("form")[:8]:
            inputs = []
            has_password = False
            for inp in form.find_all(["input", "button", "select", "textarea"]):
                info = {
                    "tag": inp.name,
                    "type": (inp.get("type") or "").lower(),
                    "name": inp.get("name") or "",
                    "placeholder": inp.get("placeholder") or "",
                    "value": inp.get("value") or "",
                }
                if info["type"] == "password":
                    has_password = True
                inputs.append(info)
            action = form.get("action") or ""
            forms.append({
                "action": action,
                "method": (form.get("method") or "get").lower(),
                "inputs": inputs,
                "has_password": has_password,
                "resolved_action": urljoin(base_url, action) if action else base_url,
            })

        links = []
        for a in soup.find_all("a", href=True)[:40]:
            links.append(urljoin(base_url, a.get("href")))

        scripts = []
        for script in soup.find_all("script")[:20]:
            src = script.get("src")
            body = script.get_text(" ", strip=True)
            scripts.append({"src": urljoin(base_url, src) if src else None, "inline_len": len(body), "inline": body[:2000]})

        image_urls = []
        for img in soup.find_all("img", src=True)[:max_images]:
            image_urls.append(urljoin(base_url, img.get("src")))

        favicon_urls = []
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            href = link.get("href") or ""
            if any(token in rel for token in ("icon", "shortcut", "apple-touch-icon", "mask-icon")):
                favicon_urls.append(urljoin(base_url, href))

        return {
            "text": text,
            "title": title,
            "meta": meta,
            "forms": forms,
            "links": links,
            "scripts": scripts,
            "image_urls": image_urls,
            "favicon_urls": list(dict.fromkeys(favicon_urls))[:6],
            "raw_html": html,
        }

    def _extract_title(self, html: str) -> str:
        soup = BeautifulSoup(html or "", "lxml")
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        return ""


    def _collect_signals(
        self,
        parsed: dict[str, Any],
        final_url: str,
        page_title: str,
        brand_name: str,
        official_domain: str,
        logo_match: bool,
        infra: dict[str, Any],
        redirects: list[str],
        public_intel,
        captcha_detected: bool = False,
    ) -> dict[str, Any]:
        host = urlparse(final_url).hostname or ""
        domain = self._registrable_domain(host)
        official_domain_reg = self._registrable_domain(official_domain) if official_domain else None
        text = (parsed.get("text") or "").lower()
        title = (page_title or parsed.get("title") or "").lower()

        brand_norm = brand_name.lower().strip()
        brand_tokens = _brand_terms(brand_name)
        brand_slug = _normalize_slug(brand_name)
        host_slug = _normalize_slug(host)
        is_local_host = host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.") or host.endswith(".local")
        brand_in_text = bool(brand_norm and brand_norm in text)
        brand_in_title = bool(brand_norm and brand_norm in title)
        brand_in_host = (not is_local_host) and (bool(brand_tokens and any(token and token in host_slug for token in brand_tokens)) or bool(brand_slug and brand_slug in host_slug))

        forms = parsed.get("forms", [])
        has_password_field = any(any((i.get("type") or "").lower() == "password" for i in form.get("inputs", [])) for form in forms)
        has_submit_button = any(any((i.get("tag") or "").lower() == "button" or (i.get("type") or "").lower() == "submit" for i in form.get("inputs", [])) for form in forms)
        hidden_inputs = sum(1 for form in forms for i in form.get("inputs", []) if (i.get("type") or "").lower() == "hidden")
        off_domain_form_action = False
        for form in forms:
            resolved_action = form.get("resolved_action") or ""
            action_host = urlparse(resolved_action).hostname or ""
            if not action_host:
                continue
            action_reg = self._registrable_domain(action_host)
            if action_reg and domain and action_reg != domain:
                off_domain_form_action = True
                break
            if action_reg and not domain and urlparse(resolved_action).scheme in {"http", "https"}:
                off_domain_form_action = True
                break

        official_owned_portal = bool(official_domain_reg and domain and (domain == official_domain_reg or host.endswith("." + official_domain_reg)) and not is_local_host)
        domain_mismatch = bool(brand_norm and official_domain_reg and domain and official_domain_reg != domain and not official_owned_portal and not is_local_host)

        keywords_hit = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in text or kw in title})
        high_risk_keyword_hit = [kw for kw in keywords_hit if kw in {"verify", "verification", "appointment", "passport", "visa", "update", "confirm", "authenticate", "otp", "two-factor", "2fa", "mfa", "unlock", "suspended", "expired", "re-enter", "recover", "reset", "checkout", "payment", "session"}]
        http_page = final_url.startswith("http://")
        iframe_present = "<iframe" in (parsed.get("raw_html") or "").lower()
        obfuscated_js = any(self._is_obfuscated_script(script.get("inline", "")) for script in parsed.get("scripts", []))

        if captcha_detected:
            # A challenge page is not a phishing page by itself, so we avoid over-scoring the usual form cues.
            has_password_field = False
            has_submit_button = False
            hidden_inputs = 0
            off_domain_form_action = False
            iframe_present = False
            obfuscated_js = False

        domain_similarity = self._domain_similarity(host, official_domain or "") if official_domain else 0.0
        suspicious_brand_keywords = []
        if brand_norm:
            for kw in ("verify", "appointment", "passport", "visa", "login", "sign in", "secure"):
                if kw in text or kw in title:
                    suspicious_brand_keywords.append(kw)

        legit_portal_hint = bool(
            official_owned_portal
            and has_password_field
            and not off_domain_form_action
            and not public_intel.urlhaus_hit
            and not logo_match
            and not obfuscated_js
            and not iframe_present
            and (brand_in_host or brand_in_text or brand_in_title)
        )

        signals = {
            "host": host,
            "domain": domain,
            "official_domain_reg": official_domain_reg,
            "official_owned_portal": official_owned_portal,
            "brand_in_text": brand_in_text,
            "brand_in_title": brand_in_title,
            "brand_in_host": brand_in_host,
            "brand_slug": brand_slug,
            "domain_mismatch": domain_mismatch,
            "has_password_field": has_password_field,
            "has_submit_button": has_submit_button,
            "off_domain_form_action": off_domain_form_action,
            "hidden_inputs_present": hidden_inputs > 0,
            "hidden_inputs_count": hidden_inputs,
            "http_page": http_page,
            "iframe_present": iframe_present,
            "obfuscated_js": obfuscated_js,
            "keywords_hit": keywords_hit,
            "high_risk_keywords": high_risk_keyword_hit,
            "suspicious_brand_keywords": suspicious_brand_keywords,
            "logo_match": logo_match,
            "domain_similarity": round(domain_similarity, 3),
            "redirect_count": len(redirects),
            "redirects": redirects,
            "threat_hit": bool(public_intel.urlhaus_hit),
            "legit_portal_hint": legit_portal_hint,
            "domain_age_days": public_intel.domain_age_days,
            "domain_created": public_intel.domain_created,
            "domain_last_changed": public_intel.domain_last_changed,
            "recently_created": public_intel.recently_created,
            "recently_updated": public_intel.recently_updated,
            "privacy_proxy": public_intel.privacy_proxy,
            "ownership_churn_indicator": public_intel.ownership_churn_indicator,
            "registrar": public_intel.registrar,
            "name_servers": public_intel.name_servers or [],
            "timeline_notes": public_intel.timeline_notes or [],
            "evidence": {
                "title": parsed.get("title") or page_title,
                "form_count": len(forms),
                "image_count": len(parsed.get("image_urls", [])),
                "brand_in_host": brand_in_host,
                "legit_portal_hint": legit_portal_hint,
                "official_owned_portal": official_owned_portal,
            },
            "hosting_provider": infra.get("provider_hint"),
            "captcha_detected": captcha_detected,
        }
        return signals


    def _score_signals(self, signals: dict[str, Any], public_intel) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        if signals["captcha_detected"]:
            reasons.append("A CAPTCHA or browser challenge was detected, so deeper page inspection was limited.")

        if signals["threat_hit"]:
            score += self.weights["urlhaus_hit"]
            reasons.append("The URL or host matches a public malicious-URL feed.")

        if signals["domain_age_days"] is not None:
            age = signals["domain_age_days"]
            if age <= 14:
                score += self.weights["recent_domain"] + 8
                reasons.append("The domain is very new, which is common in throwaway phishing infrastructure.")
            elif age <= 30:
                score += self.weights["recent_domain"]
                reasons.append("The domain was created recently.")
            elif age <= 90:
                score += 14
                reasons.append("The domain is relatively young.")
            elif age <= 180:
                score += 6
                reasons.append("The domain is not long-established.")

        if signals["recently_updated"] and signals["domain_age_days"] is not None and signals["domain_age_days"] <= 90:
            score += self.weights["updated_domain"]
            reasons.append("The domain registration data was updated recently.")

        if signals["privacy_proxy"]:
            score += self.weights["privacy_proxy"]
            reasons.append("Registrant details appear to be privacy-protected or redacted.")

        if signals["ownership_churn_indicator"] == "high":
            score += self.weights["ownership_churn"]
            reasons.append("The registration timeline shows a high-churn pattern.")
        elif signals["ownership_churn_indicator"] == "medium":
            score += 4
            reasons.append("The registration timeline looks relatively fresh or partially obscured.")

        if signals["off_domain_form_action"]:
            score += self.weights["off_domain_form_action"]
            reasons.append("A form action points to a different domain.")

        if signals["has_password_field"]:
            if signals["off_domain_form_action"]:
                score += self.weights["password_with_offdomain"]
                reasons.append("A password field is being submitted to a different domain.")
            elif not signals["official_owned_portal"]:
                score += self.weights["password_on_legit_domain"]
                reasons.append("A login field is present.")

        if signals["logo_match"]:
            score += self.weights["logo_match"]
            reasons.append("A supplied logo closely matches an on-page image.")

        if signals["domain_mismatch"]:
            mismatch_weight = self.weights["domain_mismatch"]
            score += mismatch_weight
            reasons.append("The observed domain does not match the expected official domain.")
            if signals["brand_in_host"] and not signals["official_owned_portal"]:
                score += 8
                reasons.append("Brand keywords appear on a domain that is not owned by the expected brand.")

        if (signals["brand_in_text"] or signals["brand_in_title"]) and (signals["off_domain_form_action"] or signals["logo_match"] or signals["threat_hit"] or signals["domain_mismatch"]):
            if signals["brand_in_text"]:
                score += self.weights["brand_text_match"]
                reasons.append("The brand name appears in the page text.")
            if signals["brand_in_title"]:
                score += self.weights["brand_in_title"]
                reasons.append("The brand name appears in the page title.")

        if signals["hidden_inputs_present"] and signals["has_password_field"] and signals["off_domain_form_action"]:
            score += self.weights["hidden_inputs_present"]
            reasons.append("Hidden fields are present alongside credential capture.")

        if signals["http_page"] and not signals["official_owned_portal"]:
            score += self.weights["http_page"]
            reasons.append("The page is served over plain HTTP.")

        if signals["iframe_present"]:
            score += self.weights["iframe_present"]
            reasons.append("The page contains embedded iframes.")

        if signals["obfuscated_js"]:
            score += self.weights["obfuscated_js"]
            reasons.append("JavaScript appears unusually compact or obfuscated.")

        if signals["high_risk_keywords"] and (signals["off_domain_form_action"] or signals["logo_match"] or signals["threat_hit"] or signals["domain_mismatch"]):
            score += min(16, len(signals["high_risk_keywords"]) * self.weights["suspicious_brand_keywords"])
            reasons.append("The page uses phishing-style keywords in a suspicious context.")

        if signals["domain_similarity"] >= 0.82 and signals["domain_mismatch"] and not signals["official_owned_portal"]:
            score += 4
            reasons.append("The domain is visually similar to the official domain.")

        if signals["legit_portal_hint"] and not signals["off_domain_form_action"] and not signals["threat_hit"] and not signals["logo_match"] and not signals["domain_mismatch"]:
            score = min(score, 18)
            reasons = [
                "The page looks like a branded login portal rather than a credential-harvesting clone.",
                "The host belongs to the expected brand and the login flow does not post credentials off-domain.",
            ]

        score = max(0, min(100, score))
        if score < 18 and signals["has_password_field"] and not signals["off_domain_form_action"] and not signals["domain_mismatch"]:
            reasons = ["The page looks like a normal sign-in page and no major abuse signals were found."]
        elif not reasons:
            reasons = ["No strong phishing or brand-abuse indicators were detected."]
        return score, reasons[:8]


    def _category_scores(self, signals: dict[str, Any], public_intel) -> dict[str, int]:
        phishing = 0
        brand = 0
        threat_intel = 0
        infrastructure = 0

        if signals["threat_hit"]:
            phishing += 45
        if signals["off_domain_form_action"]:
            phishing += 35
        if signals["has_password_field"] and signals["off_domain_form_action"]:
            phishing += 18
        if signals["domain_age_days"] is not None:
            if signals["domain_age_days"] <= 14:
                phishing += 18
            elif signals["domain_age_days"] <= 30:
                phishing += 14
            elif signals["domain_age_days"] <= 90:
                phishing += 8
        if signals["hidden_inputs_present"] and signals["off_domain_form_action"]:
            phishing += 4
        if signals["iframe_present"]:
            phishing += 4
        if signals["obfuscated_js"]:
            phishing += 6
        if signals["privacy_proxy"] and signals["domain_age_days"] is not None and signals["domain_age_days"] <= 90:
            phishing += 5

        if signals["logo_match"]:
            brand += 32
        if signals["domain_mismatch"]:
            brand += 18
        if signals["brand_in_host"] and not signals["official_owned_portal"]:
            brand += 16
        if (signals["brand_in_text"] or signals["brand_in_title"]) and (signals["logo_match"] or signals["off_domain_form_action"] or signals["threat_hit"] or signals["domain_mismatch"]):
            brand += 14
        if signals["domain_similarity"] >= 0.82 and signals["domain_mismatch"] and not signals["official_owned_portal"]:
            brand += 6

        if public_intel.urlhaus_hit:
            threat_intel += 65
        threat_intel += min(30, public_intel.intel_score)
        if public_intel.crtsh_hits:
            threat_intel += min(12, public_intel.crtsh_hits)
        if public_intel.domain_age_days is not None:
            if public_intel.domain_age_days <= 14:
                threat_intel += 16
            elif public_intel.domain_age_days <= 30:
                threat_intel += 12
            elif public_intel.domain_age_days <= 90:
                threat_intel += 6
        if public_intel.privacy_proxy:
            threat_intel += 4
        if public_intel.ownership_churn_indicator == 'high':
            threat_intel += 8
        elif public_intel.ownership_churn_indicator == 'medium':
            threat_intel += 4

        if public_intel.ip:
            infrastructure += 10
        if public_intel.rdap_asn:
            infrastructure += 16
        if public_intel.provider_hint:
            infrastructure += 10
        if public_intel.rdap_country:
            infrastructure += 4
        if signals["recently_updated"]:
            infrastructure += 4

        return {
            "phishing": min(100, phishing),
            "brand": min(100, brand),
            "threat_intel": min(100, threat_intel),
            "infrastructure": min(100, infrastructure),
        }


    def _insight_cards(self, signals: dict[str, Any], public_intel, target: AnalysisInput, reasons: list[str]) -> list[dict[str, Any]]:
        cards: list[dict[str, Any]] = []

        first_card_bullets = []
        if signals.get("captcha_detected"):
            first_card_bullets.append("The page was access-restricted during capture, so only passive signals were used.")
        if signals["has_password_field"]:
            first_card_bullets.append("A password field was detected on the page.")
        if signals["off_domain_form_action"]:
            first_card_bullets.append("The form submits to a different domain than the page itself.")
        if signals["domain_age_days"] is not None:
            first_card_bullets.append(f"The domain was created about {signals['domain_age_days']} day(s) ago.")
        if signals["privacy_proxy"]:
            first_card_bullets.append("The registration details are privacy-protected or partially redacted.")
        if signals["logo_match"]:
            first_card_bullets.append("The uploaded logo reference visually matches an on-page image.")
        if not first_card_bullets:
            first_card_bullets.append("The page was reviewed passively and no credential form stood out.")
        cards.append({
            "tone": "critical" if (signals["off_domain_form_action"] or signals["threat_hit"]) else ("medium" if signals["has_password_field"] else "low"),
            "title": "Evidence found on the page",
            "bullets": first_card_bullets,
        })

        reasoning = []
        if signals["domain_mismatch"]:
            reasoning.append("The observed domain does not align with the official customer domain.")
        if signals.get("captcha_detected"):
            reasoning.append("The page was access-restricted, so deeper evidence collection was limited.")
        if signals["brand_in_host"] and not signals["official_owned_portal"]:
            reasoning.append("Brand keywords appear in the host name, but the host is not the expected brand-owned domain.")
        if signals["brand_in_text"]:
            reasoning.append("The customer brand appears in the visible page text.")
        if signals["brand_in_title"]:
            reasoning.append("The brand is also used in the title.")
        if signals["domain_age_days"] is not None and signals["domain_age_days"] <= 30:
            reasoning.append("The domain is freshly registered, which is a common phishing trait.")
        if signals["recently_updated"] and signals["domain_age_days"] is not None and signals["domain_age_days"] <= 90:
            reasoning.append("The registration data was updated recently, which raises churn suspicion.")
        if signals["high_risk_keywords"]:
            reasoning.append("The page uses login or verification language in a suspicious context.")
        if not reasoning:
            reasoning.append("No strong brand-abuse or credential-harvesting pattern was confirmed in this pass.")
        cards.append({
            "tone": "high" if (signals["domain_mismatch"] or signals["off_domain_form_action"] or signals["logo_match"]) else "medium",
            "title": "Why the risk score moved",
            "bullets": reasoning,
        })

        intel_lines = []
        if public_intel.urlhaus_hit:
            intel_lines.append("The URL or host matched the public malicious-URL feed.")
        if public_intel.crtsh_hits:
            intel_lines.append(f"Certificate Transparency search returned {public_intel.crtsh_hits} related result(s).")
        if public_intel.provider_hint:
            intel_lines.append(f"Hosting appears to be on {public_intel.provider_hint}.")
        if public_intel.domain_created:
            intel_lines.append(f"Created: {public_intel.domain_created.split('T')[0]}.")
        if public_intel.domain_last_changed:
            intel_lines.append(f"Last changed: {public_intel.domain_last_changed.split('T')[0]}.")
        if public_intel.ownership_churn_indicator != 'unknown':
            intel_lines.append(f"Ownership churn indicator: {public_intel.ownership_churn_indicator}.")
        if not intel_lines:
            intel_lines.append("No free public threat-intel source produced a strong hit.")
        cards.append({"tone": "medium", "title": "Threat intelligence and timeline", "bullets": intel_lines})

        action = []
        if signals.get("captcha_detected"):
            action.append("Mark the page as access-restricted and review passive evidence only.")
            action.append("Check the domain timeline and public reputation before escalating.")
        if signals["threat_hit"] or (signals["has_password_field"] and signals["off_domain_form_action"]) or signals["logo_match"] or (signals["domain_age_days"] is not None and signals["domain_age_days"] <= 30 and signals["domain_mismatch"]):
            action.append("Block or quarantine the URL for review.")
            action.append("Preserve the screenshot, redirect chain, and form action as evidence.")
            action.append("Escalate quickly if the customer confirms they do not own this domain.")
        elif signals["official_owned_portal"] and signals["has_password_field"]:
            action.append("Treat this as a watch item until the customer confirms ownership of the portal.")
            action.append("Use the screenshot, host name, and form destination together before escalating.")
        else:
            action.append("Monitor the URL and add it to watchlists if it reappears.")
            action.append("Check whether the brand is being used without permission on a different domain.")
        cards.append({"tone": "low", "title": "Recommended next step", "bullets": action})
        return cards[:4]


    def _summary(self, signals: dict[str, Any], reasons: list[str], brand_name: str, official_domain: str, public_intel) -> str:
        brand = brand_name or "the referenced brand"
        if signals.get("captcha_detected") and not (signals["threat_hit"] or signals["off_domain_form_action"]):
            if signals["domain_age_days"] is not None and signals["domain_age_days"] <= 30:
                return "The page was access-restricted, and the domain is very new. That combination deserves review even though the page content could not be fully accessed."
            return "The page was access-restricted, so deeper inspection was limited to passive infrastructure and timeline signals."
        if signals["threat_hit"] or (signals["off_domain_form_action"] and signals["has_password_field"]):
            if signals["domain_age_days"] is not None and signals["domain_age_days"] <= 30:
                return f"The page shows a credential-harvesting pattern on a very new domain, which is a strong phishing signal for {brand}."
            return "The page shows a credential-harvesting pattern, with supporting evidence from the form behavior and public threat-intel checks."
        if signals["domain_mismatch"] or (signals["brand_in_host"] and not signals["official_owned_portal"]):
            return f"The page appears to imitate {brand}. The host name, brand usage, and domain timeline deserve review."
        if signals["official_owned_portal"] and signals["has_password_field"]:
            return f"The page looks like a branded login portal for {brand}. The host belongs to the expected domain and the current pass does not show a strong phishing pattern."
        if signals["has_password_field"] and not signals["off_domain_form_action"]:
            return "The page looks like a routine sign-in form and no strong brand-abuse or malicious-hosting signals were found."
        return "No strong phishing or brand-impersonation signal was detected from the current pass."

    def _verdict(self, score: int) -> str:
        if score >= 70:
            return "high-risk"
        if score >= 35:
            return "suspicious"
        return "low-risk"

    def _match_logos(
        self,
        reference_logos: list[bytes],
        image_urls: list[str],
        screenshot_path: str | None = None,
        favicon_urls: list[str] | None = None,
    ) -> tuple[bool, list[dict[str, Any]]]:
        if not reference_logos:
            return False, []

        refs: list[tuple[str, Image.Image]] = []
        for blob in reference_logos:
            ref_img = _load_image_from_bytes(blob)
            if ref_img is None:
                continue
            refs.append((hashlib.sha1(blob).hexdigest()[:8], ref_img))
        if not refs:
            return False, []

        candidates: list[tuple[str, Image.Image]] = []

        def add_candidate(label: str, img: Image.Image | None) -> None:
            if img is None:
                return
            base = img.convert("RGB")
            candidates.append((label, base))
            for idx, crop in enumerate(_crop_candidates(base)):
                if idx == 0:
                    continue
                candidates.append((f"{label}#crop{idx}", crop.convert("RGB")))

        # Website-provided images.
        for idx, url in enumerate((image_urls or [])[:6]):
            try:
                if url.startswith("data:"):
                    continue
                resp = __import__("requests").get(url, timeout=6, headers={"User-Agent": "BrandGuardDemo/4.0"})
                if resp.status_code >= 400 or "image" not in resp.headers.get("content-type", "").lower():
                    continue
                add_candidate(f"page-image-{idx}", _load_image_from_bytes(resp.content))
            except Exception:
                continue

        # Favicons often contain brand marks or monograms.
        for idx, url in enumerate((favicon_urls or [])[:4]):
            try:
                if url.startswith("data:"):
                    continue
                resp = __import__("requests").get(url, timeout=5, headers={"User-Agent": "BrandGuardDemo/4.0"})
                if resp.status_code >= 400 or "image" not in resp.headers.get("content-type", "").lower():
                    continue
                add_candidate(f"favicon-{idx}", _load_image_from_bytes(resp.content))
            except Exception:
                continue

        # The screenshot is the most useful source when the logo is rendered as part of the page.
        if screenshot_path:
            try:
                shot_path = Path(screenshot_path)
                if not shot_path.is_absolute():
                    shot_path = OUTPUT_DIR / shot_path.name if shot_path.name else OUTPUT_DIR / str(shot_path)
                add_candidate("screenshot", _load_image_from_path(shot_path))
            except Exception:
                pass

        matches: list[dict[str, Any]] = []
        best = False
        seen_pairs: set[tuple[str, str]] = set()

        for ref_id, ref_img in refs:
            ref_best: dict[str, Any] | None = None
            best_conf = -1
            best_dist = 10**9
            for cand_label, cand_img in candidates:
                try:
                    dist, confidence = _logo_similarity_score(ref_img, cand_img)
                    if confidence >= 62 and (dist < best_dist or confidence > best_conf):
                        best = True
                        best_conf = confidence
                        best_dist = dist
                        ref_best = {
                            "image_source": cand_label,
                            "reference_id": ref_id,
                            "distance": int(dist),
                            "confidence": int(confidence),
                        }
                except Exception:
                    continue
            if ref_best:
                pair_key = (ref_best["reference_id"], ref_best["image_source"])
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    matches.append(ref_best)

        return best, matches

    def _build_infrastructure(self, final_url: str, public_intel) -> dict[str, Any]:
        host = urlparse(final_url).hostname
        return {
            'host': host,
            'ip': public_intel.ip,
            'asn': public_intel.rdap_asn,
            'asn_description': public_intel.rdap_asn_description,
            'country': public_intel.rdap_country,
            'network': public_intel.rdap_network,
            'provider_hint': public_intel.provider_hint,
            'registrable_domain': self._registrable_domain(host) if host else None,
            'registrar': public_intel.registrar,
            'name_servers': public_intel.name_servers or [],
            'domain_created': public_intel.domain_created,
            'domain_last_changed': public_intel.domain_last_changed,
            'domain_age_days': public_intel.domain_age_days,
            'privacy_proxy': public_intel.privacy_proxy,
            'ownership_churn_indicator': public_intel.ownership_churn_indicator,
            'timeline_notes': public_intel.timeline_notes or [],
        }

    def _same_brandish_domain(self, a: str, b: str) -> bool:
        return self._registrable_domain(a) == self._registrable_domain(b)

    def _brand_slug_match(self, brand_name: str, host: str) -> bool:
        brand_slug = _normalize_slug(brand_name)
        host_slug = _normalize_slug(host)
        if not brand_slug or not host_slug:
            return False
        return brand_slug in host_slug

    def _registrable_domain(self, hostname: str | None) -> str | None:
        if not hostname:
            return None
        host = hostname.lower().strip('.')
        parts = host.split('.')
        if len(parts) <= 2:
            return host
        if parts[-2] in COMMON_SLD_SUFFIXES and len(parts) >= 3:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def _domain_similarity(self, a: str, b: str) -> float:
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a.lower(), b.lower()).ratio()

    def _is_obfuscated_script(self, text: str) -> bool:
        if not text:
            return False
        compact = re.sub(r"\s+", "", text)
        if len(compact) < 180:
            return False
        if compact.count(';') > 18 and len(compact) < 1200:
            return True
        if re.search(r"eval\(|atob\(|fromCharCode\(|document\.write\(", compact):
            return True
        return False
