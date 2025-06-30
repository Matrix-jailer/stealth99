"""
Stealth Gateway Detection API

- Uses Playwright (async) for DOM, buttons, iframes, JS rendering, shadow roots
- Uses undetected-chromedriver + selenium-wire for network capture
- Uses concurrency and link indicators like /checkout, /cart, /payment, etc.
- Detects: gateways, 3D secure, captcha, cloudflare, platform, graphql
- Includes API interface via FastAPI
"""

import asyncio
import time
import re
from typing import List, Dict, Set, Any
from urllib.parse import urljoin, urlparse
from fastapi import FastAPI, Query
from pydantic import BaseModel
from playwright.async_api import async_playwright
import tls_client
import logging

# --- PLACEHOLDER: Paste your keyword detection dicts from GhostAPIPRO v2 below ---
# PAYMENT_GATEWAY_KEYWORDS = {...}
# CAPTCHA_KEYWORDS = [...]
# THREE_DS_KEYWORDS = [...]
# PLATFORM_KEYWORDS = {...}
# GRAPHQL_KEYWORDS = [...]

# --- Detection indicators ---
INDICATOR_PATHS = ["cart", "checkout", "payment", "billing", "add-to-cart"]

# --- App setup ---
app = FastAPI()
logger = logging.getLogger("stealth_gateway_api")

class ScanResult(BaseModel):
    url: str
    gateways: List[str]
    captcha: List[str]
    three_ds: bool
    cloudflare: bool
    platform: str
    graphql: bool
    time_taken: float

class StealthGatewayScanner:
    def __init__(self):
        self.visited: Set[str] = set()
        self.collected: Set[str] = set()
        self.session = tls_client.Session(client_identifier="chrome_120")

    def is_relevant_url(self, url: str) -> bool:
        url = url.lower()
        return any(ind in url for ind in INDICATOR_PATHS)

    async def get_candidate_urls(self, page, base_url: str) -> Set[str]:
        urls = set()
        for selector in ["a", "form", "button"]:
            elements = await page.query_selector_all(selector)
            for el in elements:
                href = await el.get_attribute("href") or await el.get_attribute("action")
                if href:
                    full = urljoin(base_url, href)
                    if self.is_relevant_url(full):
                        urls.add(full)
                onclick = await el.get_attribute("onclick")
                if onclick:
                    matches = re.findall(r'"(https?://[^"]+|/[^"\s]+)"', onclick)
                    for m in matches:
                        full = urljoin(base_url, m)
                        if self.is_relevant_url(full):
                            urls.add(full)
        return urls

    async def analyze_page_playwright(self, page, url: str) -> Dict[str, Any]:
        data = {
            "gateways": set(), "captcha": set(), "three_ds": False,
            "cloudflare": False, "platform": None, "graphql": False
        }
        try:
            await page.goto(url, timeout=30000)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)
            content = await page.content()
            # --- SHADOW DOM & iframe exploration can be added here if needed ---
            if any(k in content for k in CAPTCHA_KEYWORDS):
                data["captcha"].update(CAPTCHA_KEYWORDS)
            if any(k in content for k in THREE_DS_KEYWORDS):
                data["three_ds"] = True
            for plat, indicators in PLATFORM_KEYWORDS.items():
                if any(k in content for k in indicators):
                    data["platform"] = plat
            for name, patterns in PAYMENT_GATEWAY_KEYWORDS.items():
                if any(k in content for k in patterns):
                    data["gateways"].add(name)
            if any(k in content for k in GRAPHQL_KEYWORDS):
                data["graphql"] = True
            if "__cf_chl" in url or "cf_clearance" in content:
                data["cloudflare"] = True
        except Exception as e:
            logger.error(f"Playwright page error: {e}")
        return data

    async def playwright_worker(self, browser, url, results):
        page = await browser.new_page()
        await page.add_init_script(path="stealth.min.js")
        result = await self.analyze_page_playwright(page, url)
        results.append(result)
        await page.close()

    async def playwright_scan(self, urls: Set[str]) -> List[Dict[str, Any]]:
        results = []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            tasks = [self.playwright_worker(browser, u, results) for u in urls]
            await asyncio.gather(*tasks)
            await browser.close()
        return results

    def selenium_wire_scan(self, urls: Set[str]) -> List[Dict[str, Any]]:
        from seleniumwire.undetected_chromedriver.v2 import Chrome, ChromeOptions
        chrome_options = ChromeOptions()
        chrome_options.headless = True
        driver = Chrome(options=chrome_options)

        results = []
        try:
            for url in urls:
                driver.get(url)
                time.sleep(3)
                raw = driver.page_source
                result = {"gateways": set(), "captcha": set(), "three_ds": False}
                for name, sigs in PAYMENT_GATEWAY_KEYWORDS.items():
                    if any(s in raw for s in sigs):
                        result["gateways"].add(name)
                if any(s in raw for s in CAPTCHA_KEYWORDS):
                    result["captcha"].update(CAPTCHA_KEYWORDS)
                if any(s in raw for s in THREE_DS_KEYWORDS):
                    result["three_ds"] = True
                for req in driver.requests:
                    if req.response:
                        body = (req.body or b"").decode(errors="ignore") + (req.response.body or b"").decode(errors="ignore")
                        if any(gw in body for sigs in PAYMENT_GATEWAY_KEYWORDS.values() for gw in sigs):
                            result["gateways"].add(gw)
                results.append(result)
        except Exception as e:
            logger.error(f"Selenium Wire error: {e}")
        finally:
            driver.quit()
        return results

    async def full_scan(self, url: str) -> ScanResult:
        start = time.time()
        self.visited = {url}
        candidate_urls = {url}

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url)
            found = await self.get_candidate_urls(page, url)
            candidate_urls.update(found)
            await browser.close()

        playwright_results = await self.playwright_scan(candidate_urls)
        selenium_results = self.selenium_wire_scan(candidate_urls)

        # Aggregate
        result = ScanResult(
            url=url,
            gateways=[],
            captcha=[],
            three_ds=False,
            cloudflare=False,
            platform=None,
            graphql=False,
            time_taken=round(time.time() - start, 2)
        )

        for r in playwright_results + selenium_results:
            result.gateways.extend(r.get("gateways", []))
            result.captcha.extend(r.get("captcha", []))
            if r.get("three_ds"):
                result.three_ds = True
            if r.get("cloudflare"):
                result.cloudflare = True
            if r.get("platform") and not result.platform:
                result.platform = r["platform"]
            if r.get("graphql"):
                result.graphql = True

        result.gateways = list(set(result.gateways))
        result.captcha = list(set(result.captcha))
        return result

scanner = StealthGatewayScanner()

@app.get("/scan", response_model=ScanResult)
async def scan(url: str = Query(..., description="Target website URL")):
    return await scanner.full_scan(url)
