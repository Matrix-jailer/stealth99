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
        logger.info(f"[Extracting Links] From base URL: {base_url}")
        for selector in ["a", "form", "button"]:
            elements = await page.query_selector_all(selector)
            logger.info(f"[{selector}] Found {len(elements)} elements.")
            for el in elements:
                href = await el.get_attribute("href") or await el.get_attribute("action")
                if href:
                    full = urljoin(base_url, href)
                    if self.is_relevant_url(full) and full not in self.visited:
                        logger.info(f"[Relevant URL] Found via href/action: {full}")
                        urls.add(full)
                onclick = await el.get_attribute("onclick")
                if onclick:
                    matches = re.findall(r'"(https?://[^"]+|/[^"\s]+)"', onclick)
                    for m in matches:
                        full = urljoin(base_url, m)
                        if self.is_relevant_url(full) and full not in self.visited:
                            logger.info(f"[Relevant URL] Found via onclick JS: {full}")
                            urls.add(full)
        return urls

    async def analyze_page_playwright(self, browser, url: str) -> Dict[str, Any]:
        data = {
            "gateways": set(), "captcha": set(), "three_ds": False,
            "cloudflare": False, "platform": None, "graphql": False
        }
        logger.info(f"[Playwright] Analyzing: {url}")
        page = await browser.new_page()
        await page.add_init_script(path="stealth.min.js")
        try:
            await page.goto(url, timeout=30000)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)
            content = await page.content()

            for captcha_type, keywords in CAPTCHA_KEYWORDS.items():
                if any(kw.lower() in content.lower() for kw in keywords):
                    logger.info(f"[CAPTCHA] Found {captcha_type} on {url}")
                    data["captcha"].add(captcha_type)

            if any(pattern.search(content) for pattern in THREE_DS_KEYWORDS):
                logger.info(f"[3D Secure] Found on {url}")
                data["three_ds"] = True

            for plat_keyword, plat_name in PLATFORM_KEYWORDS.items():
                if plat_keyword.lower() in content.lower():
                    logger.info(f"[Platform] Detected {plat_name} on {url}")
                    data["platform"] = plat_name

            for name, patterns in PAYMENT_GATEWAY_KEYWORDS.items():
                if any(p.search(content) for p in patterns):
                    logger.info(f"[Gateway] Detected {name} on {url}")
                    data["gateways"].add(name)

            if any(p.search(content) for p in GRAPHQL_KEYWORDS):
                logger.info(f"[GraphQL] Found on {url}")
                data["graphql"] = True

            if "__cf_chl" in url or "cf_clearance" in content:
                logger.info(f"[Cloudflare] Challenge Detected on {url}")
                data["cloudflare"] = True

        except Exception as e:
            logger.error(f"[Playwright Error] on {url}: {e}")
        finally:
            await page.close()
        return data

    async def playwright_worker(self, browser, queue: asyncio.Queue, results: List[Dict[str, Any]], semaphore: asyncio.Semaphore):
        while not queue.empty():
            url = await queue.get()
            if url in self.visited:
                logger.info(f"[Playwright Worker] Skipping visited: {url}")
                queue.task_done()
                continue
            self.visited.add(url)
            async with semaphore:
                result = await self.analyze_page_playwright(browser, url)
                results.append(result)
            queue.task_done()

    async def playwright_scan(self, urls: Set[str], concurrency: int = 5) -> List[Dict[str, Any]]:
        logger.info(f"[Playwright Scan] Total URLs to scan: {len(urls)} with concurrency {concurrency}")
        results = []
        queue = asyncio.Queue()
        for u in urls:
            await queue.put(u)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            semaphore = asyncio.Semaphore(concurrency)
            workers = [self.playwright_worker(browser, queue, results, semaphore) for _ in range(concurrency)]
            await asyncio.gather(*workers)
            await browser.close()
        return results

    def selenium_wire_scan(self, urls: Set[str]) -> List[Dict[str, Any]]:
        from seleniumwire.undetected_chromedriver.v2 import Chrome, ChromeOptions
        chrome_options = ChromeOptions()
        chrome_options.headless = True
        driver = Chrome(options=chrome_options)

        logger.info(f"[Selenium Wire Scan] Starting on {len(urls)} URLs")
        results = []
        try:
            for url in urls:
                if url in self.visited:
                    logger.info(f"[Selenium] Skipping visited: {url}")
                    continue
                self.visited.add(url)
                driver.get(url)
                time.sleep(3)
                raw = driver.page_source
                result = {"gateways": set(), "captcha": set(), "three_ds": False}

                for name, sigs in PAYMENT_GATEWAY_KEYWORDS.items():
                    if any(s in raw for s in sigs):
                        logger.info(f"[Selenium Gateway] Found {name} on {url}")
                        result["gateways"].add(name)

                if any(s in raw for s in CAPTCHA_KEYWORDS):
                    logger.info(f"[Selenium CAPTCHA] Detected on {url}")
                    result["captcha"].update(CAPTCHA_KEYWORDS)

                if any(s in raw for s in THREE_DS_KEYWORDS):
                    logger.info(f"[Selenium 3D Secure] Found on {url}")
                    result["three_ds"] = True

                for req in driver.requests:
                    if req.response:
                        body = (req.body or b"").decode(errors="ignore") + (req.response.body or b"").decode(errors="ignore")
                        for name, sigs in PAYMENT_GATEWAY_KEYWORDS.items():
                            if any(sig.search(body) for sig in sigs):
                                logger.info(f"[Selenium Req Gateway] Found {name} in network on {url}")
                                result["gateways"].add(name)

                results.append(result)

        except Exception as e:
            logger.error(f"[Selenium Wire Error] {e}")
        finally:
            driver.quit()
        return results

    async def full_scan(self, url: str) -> ScanResult:
        start = time.time()
        self.visited = {url}
        candidate_urls = {url}
        logger.info(f"[Scan Start] {url}")

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                await page.goto(url)
                logger.info(f"[Main Page Loaded] {url}")
                found = await self.get_candidate_urls(page, url)
                candidate_urls.update(found)
                logger.info(f"[Link Discovery] Found {len(found)} candidate URLs")
            except Exception as e:
                logger.error(f"[Initial Page Error] {url}: {e}")
            await browser.close()

        playwright_results = await self.playwright_scan(candidate_urls, concurrency=5)
        selenium_results = self.selenium_wire_scan(candidate_urls)

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
        logger.info(f"[Scan Complete] {url} in {result.time_taken}s")
        logger.info(f"  ▸ Gateways: {result.gateways}")
        logger.info(f"  ▸ CAPTCHA: {result.captcha}")
        logger.info(f"  ▸ 3DS: {result.three_ds} | Cloudflare: {result.cloudflare} | Platform: {result.platform} | GraphQL: {result.graphql}")
        return result
