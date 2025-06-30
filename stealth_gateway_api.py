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
PAYMENT_GATEWAY_KEYWORDS = {
    "stripe": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'stripe\.com', r'api\.stripe\.com/v1', r'js\.stripe\.com', r'stripe\.js', r'stripe\.min\.js',
        r'client_secret', r'payment_intent', r'data-stripe', r'stripe-payment-element',
        r'stripe-elements', r'stripe-checkout', r'hooks\.stripe\.com', r'm\.stripe\.network',
        r'stripe__input', r'stripe-card-element', r'stripe-v3ds', r'confirmCardPayment',
        r'createPaymentMethod', r'stripePublicKey', r'stripe\.handleCardAction',
        r'elements\.create', r'js\.stripe\.com/v3/hcaptcha-invisible', r'js\.stripe\.com/v3',
        r'stripe\.createToken', r'stripe-payment-request', r'stripe__frame',
        r'api\.stripe\.com/v1/payment_methods', r'js\.stripe\.com', r'api\.stripe\.com/v1/tokens',
        r'stripe\.com/docs', r'checkout\.stripe\.com', r'stripe-js', r'stripe-redirect',
        r'stripe-payment', r'stripe\.network', r'stripe-checkout\.js'
    ]],
    "paypal": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.paypal\.com', r'paypal\.com', r'paypal-sdk\.com', r'paypal\.js', r'paypalobjects\.com', r'paypal_express_checkout', r'e\.PAYPAL_EXPRESS_CHECKOUT',
        r'paypal-button', r'paypal-checkout-sdk', r'paypal-sdk\.js', r'paypal-smart-button', r'paypal_express_checkout/api',
        r'paypal-rest-sdk', r'paypal-transaction', r'itch\.io/api-transaction/paypal',
        r'PayPal\.Buttons', r'paypal\.Buttons', r'data-paypal-client-id', r'paypal\.com/sdk/js',
        r'paypal\.Order\.create', r'paypal-checkout-component', r'api-m\.paypal\.com', r'paypal-funding',
        r'paypal-hosted-fields', r'paypal-transaction-id', r'paypal\.me', r'paypal\.com/v2/checkout',
        r'paypal-checkout', r'paypal\.com/api', r'sdk\.paypal\.com', r'gotopaypalexpresscheckout'
    ]],
    "braintree": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.braintreegateway\.com/v1', r'braintreepayments\.com', r'js\.braintreegateway\.com',
        r'client_token', r'braintree\.js', r'braintree-hosted-fields', r'braintree-dropin', r'braintree-v3',
        r'braintree-client', r'braintree-data-collector', r'braintree-payment-form', r'braintree-3ds-verify',
        r'client\.create', r'braintree\.min\.js', r'assets\.braintreegateway\.com', r'braintree\.setup',
        r'data-braintree', r'braintree\.tokenize', r'braintree-dropin-ui', r'braintree\.com'
    ]],
    "adyen": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkoutshopper-live\.adyen\.com', r'adyen\.com/hpp', r'adyen\.js', r'data-adyen',
        r'adyen-checkout', r'adyen-payment', r'adyen-components', r'adyen-encrypted-data',
        r'adyen-cse', r'adyen-dropin', r'adyen-web-checkout', r'live\.adyen-services\.com',
        r'adyen\.encrypt', r'checkoutshopper-test\.adyen\.com', r'adyen-checkout__component',
        r'adyen\.com/v1', r'adyen-payment-method', r'adyen-action', r'adyen\.min\.js', r'adyen\.com'
    ]],
    "authorize.net": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'authorize\.net/gateway/transact\.dll', r'js\.authorize\.net/v1/Accept\.js', r'js\.authorize\.net',
        r'anet\.js', r'data-authorize', r'authorize-payment', r'apitest\.authorize\.net',
        r'accept\.authorize\.net', r'api\.authorize\.net', r'authorize-hosted-form',
        r'merchantAuthentication', r'data-api-login-id', r'data-client-key', r'Accept\.dispatchData',
        r'api\.authorize\.net/xml/v1', r'accept\.authorize\.net/payment', r'authorize\.net/profile'
    ]],
    "square": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'squareup\.com', r'js\.squarecdn\.com', r'square\.js', r'data-square', r'square-payment-form',
        r'square-checkout-sdk', r'connect\.squareup\.com', r'square\.min\.js', r'squarecdn\.com',
        r'squareupsandbox\.com', r'sandbox\.web\.squarecdn\.com', r'square-payment-flow', r'square\.card',
        r'squareup\.com/payments', r'data-square-application-id', r'square\.createPayment'
    ]],
    "klarna": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'klarna\.com', r'js\.klarna\.com', r'klarna\.js', r'data-klarna', r'klarna-checkout',
        r'klarna-onsite-messaging', r'playground\.klarna\.com', r'klarna-payments', r'klarna\.min\.js',
        r'klarna-order-id', r'klarna-checkout-container', r'klarna-load', r'api\.klarna\.com'
    ]],
    "checkout.com": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.checkout\.com', r'cko\.js', r'data-checkout', r'checkout-sdk', r'checkout-payment',
        r'js\.checkout\.com', r'secure\.checkout\.com', r'checkout\.frames\.js', r'api\.sandbox\.checkout\.com',
        r'cko-payment-token', r'checkout\.init', r'cko-hosted', r'checkout\.com/v2', r'cko-card-token'
    ]],
    "razorpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.razorpay\.com', r'razorpay\.js', r'data-razorpay', r'razorpay-checkout',
        r'razorpay-payment-api', r'razorpay-sdk', r'razorpay-payment-button', r'razorpay-order-id',
        r'api\.razorpay\.com', r'razorpay\.min\.js', r'payment_box payment_method_razorpay',
        r'razorpay', r'cdn\.razorpay\.com', r'rzp_payment_icon\.svg', r'razorpay\.checkout',
        r'data-razorpay-key', r'razorpay_payment_id', r'checkout\.razorpay\.com/v1', r'razorpay-hosted'
    ]],
    "paytm": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'securegw\.paytm\.in', r'api\.paytm\.com', r'paytm\.js', r'data-paytm', r'paytm-checkout',
        r'paytm-payment-sdk', r'paytm-wallet', r'paytm\.allinonesdk', r'securegw-stage\.paytm\.in',
        r'paytm\.min\.js', r'paytm-transaction-id', r'paytm\.invoke', r'paytm-checkout-js',
        r'data-paytm-order-id'
    ]],
    "Shopify Payments": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.shopify\.com', r'data-shopify-payments', r'shopify-checkout-sdk', r'shopify-payment-api',
        r'shopify-sdk', r'shopify-express-checkout', r'shopify_payments\.js', r'checkout\.shopify\.com',
        r'shopify-payment-token', r'shopify\.card', r'shopify-checkout-api', r'data-shopify-checkout',
        r'shopify\.com/api'
    ]],
    "worldpay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'secure\.worldpay\.com', r'worldpay\.js', r'data-worldpay', r'worldpay-checkout',
        r'worldpay-payment-sdk', r'worldpay-secure', r'secure-test\.worldpay\.com', r'worldpay\.min\.js',
        r'worldpay\.token', r'worldpay-payment-form', r'access\.worldpay\.com', r'worldpay-3ds',
        r'data-worldpay-token'
    ]],
    "2checkout": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'www\.2checkout\.com', r'2co\.js', r'data-2checkout', r'2checkout-payment', r'secure\.2co\.com',
        r'2checkout-hosted', r'api\.2checkout\.com', r'2co\.min\.js', r'2checkout\.token', r'2co-checkout',
        r'data-2co-seller-id', r'2checkout\.convertplus', r'secure\.2co\.com/v2'
    ]],
    "Amazon pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'payments\.amazon\.com', r'amazonpay\.js', r'data-amazon-pay', r'amazon-pay-button',
        r'amazon-pay-checkout-sdk', r'amazon-pay-wallet', r'amazon-checkout\.js', r'payments\.amazon\.com/v2',
        r'amazon-pay-token', r'amazon-pay-sdk', r'data-amazon-pay-merchant-id', r'amazon-pay-signin',
        r'amazon-pay-checkout-session'
    ]],
    "Apple pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'apple-pay\.js', r'data-apple-pay', r'apple-pay-button', r'apple-pay-checkout-sdk',
        r'apple-pay-session', r'apple-pay-payment-request', r'ApplePaySession', r'apple-pay-merchant-id',
        r'apple-pay-payment', r'apple-pay-sdk', r'data-apple-pay-token', r'apple-pay-checkout',
        r'apple-pay-domain'
    ]],
    "Google pay": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'pay\.google\.com', r'googlepay\.js', r'data-google-pay', r'google-pay-button',
        r'google-pay-checkout-sdk', r'google-pay-tokenization', r'payments\.googleapis\.com',
        r'google\.payments\.api', r'google-pay-token', r'google-pay-payment-method',
        r'data-google-pay-merchant-id', r'google-pay-checkout', r'google-pay-sdk'
    ]],
    "mollie": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'api\.mollie\.com', r'mollie\.js', r'data-mollie', r'mollie-checkout', r'mollie-payment-sdk',
        r'mollie-components', r'mollie\.min\.js', r'profile\.mollie\.com', r'mollie-payment-token',
        r'mollie-create-payment', r'data-mollie-profile-id', r'mollie-checkout-form', r'mollie-redirect'
    ]],
    "opayo": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'live\.opayo\.eu', r'opayo\.js', r'data-opayo', r'opoayo-checkout', r'opayo-payment-sdk',
        r'opayo-form', r'test\.opayo\.eu', r'opayo\.min\.js', r'opayo-payment-token', r'opayo-3ds',
        r'data-opayo-merchant-id', r'opayo-hosted', r'opayo\.api'
    ]],
    "paddle": [re.compile(pattern, re.IGNORECASE) for pattern in [
        r'checkout\.paddle\.com', r'paddle_button\.js', r'paddle\.js', r'data-paddle',
        r'paddle-checkout-sdk', r'paddle-product-id', r'api\.paddle\.com', r'paddle\.min\.js',
        r'paddle-checkout', r'data-paddle-vendor-id', r'paddle\.Checkout\.open', r'paddle-transaction-id',
        r'paddle-hosted'
    ]]
}

# Payment indicators
PAYMENT_INDICATOR_REGEX = [
    re.compile(rf"\b{kw}\b", re.IGNORECASE)
    for kw in [
        "cart", "checkout", "payment", "buy", "purchase", "order", "billing", "subscribe",
        "shop", "store", "pricing", "add-to-cart", "pay-now", "secure-checkout", "complete-order",
        "transaction", "invoice", "checkout2", "donate", "donation", "add-to-bag", "add-to-basket",
        "shop-now", "buy-now", "order-now", "proceed-to-checkout", "pay", "payment-method",
        "credit-card", "debit-card", "place-order", "confirm-purchase", "get-started",
        "sign-up", "join-now", "membership", "upgrade", "renew", "trial", "subscribe-now",
        "book-now", "reserve", "fund", "pledge", "support", "contribute",
        "complete-purchase", "finalize-order", "payment-details", "billing-info",
        "secure-payment", "pay-securely", "shop-secure", "give", "donate-now", "donatenow",
        "donate_now", "get-now", "browse", "category", "items", "product", "item",
        "giftcard", "topup", "plans", "buynow", "sell", "sell-now", "purchase-now",
        "shopnow", "shopping", "menu", "games",
        "sale", "vps", "server", "about", "about-us",
        "cart-items", "buy-secure", "cart-page", "checkout-page",
        "order-summary", "payment-form", "purchase-flow", "shop-cart", "ecommerce", "store-cart",
        "buy-button", "purchase-button", "add-item", "remove-item", "cart-update",
        "apply-coupon", "redeem-code", "discount-code", "promo-code", "gift-card", "pay-with",
        "payment-options", "express-checkout", "quick-buy", "one-click-buy", "instant-purchase"
    ]
]
CAPTCHA_KEYWORDS = {
    "reCaptcha": [
        "g-recaptcha", "recaptcha/api.js", "data-sitekey", "nocaptcha",
        "recaptcha.net", "www.google.com/recaptcha", "grecaptcha.execute",
        "grecaptcha.render", "grecaptcha.ready", "recaptcha-token"
    ],
    "hCaptcha": [
        "hcaptcha", "assets.hcaptcha.com", "hcaptcha.com/1/api.js",
        "data-hcaptcha-sitekey", "js.stripe.com/v3/hcaptcha-invisible", "hcaptcha-invisible", "hcaptcha.execute"
    ],
    "Turnstile": [
        "turnstile", "challenges.cloudflare.com", "cf-turnstile-response",
        "data-sitekey", "__cf_chl_", "cf_clearance"
    ],
    "Arkose Labs": [
        "arkose-labs", "funcaptcha", "client-api.arkoselabs.com",
        "fc-token", "fc-widget", "arkose", "press and hold", "funcaptcha.com"
    ],
    "GeeTest": [
        "geetest", "gt_captcha_obj", "gt.js", "geetest_challenge",
        "geetest_validate", "geetest_seccode"
    ],
    "BotDetect": [
        "botdetectcaptcha", "BotDetect", "BDC_CaptchaImage", "CaptchaCodeTextBox"
    ],
    "KeyCAPTCHA": [
        "keycaptcha", "kc_submit", "kc__widget", "s_kc_cid"
    ],
    "Anti Bot Detection": [
        "fingerprintjs", "js.challenge", "checking your browser",
        "verify you are human", "please enable javascript and cookies",
        "sec-ch-ua-platform"
    ],
    "Captcha": [
        "captcha-container", "captcha-box", "captcha-frame", "captcha_input",
        "id=\"captcha\"", "class=\"captcha\"", "iframe.+?captcha",
        "data-captcha-sitekey"
    ]
}

THREE_D_SECURE_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'three_d_secure', r'3dsecure', r'acs', r'acs_url', r'acsurl', r'redirect',
    r'secure-auth', r'three_d_secure_usage', r'challenge', r'3ds', r'3ds1', r'3ds2', r'tds', r'tdsecure',
    r'3d-secure', r'three-d', r'3dcheck', r'3d-auth', r'three-ds',
    r'stripe\.com/3ds', r'm\.stripe\.network', r'hooks\.stripe\.com/3ds',
    r'paddle_frame', r'paddlejs', r'secure\.paddle\.com', r'buy\.paddle\.com',
    r'idcheck', r'garanti\.com\.tr', r'adyen\.com/hpp', r'adyen\.com/checkout',
    r'adyenpayments\.com/3ds', r'auth\.razorpay\.com', r'razorpay\.com/3ds',
    r'secure\.razorpay\.com', r'3ds\.braintreegateway\.com', r'verify\.3ds',
    r'checkout\.com/3ds', r'checkout\.com/challenge', r'3ds\.paypal\.com',
    r'authentication\.klarna\.com', r'secure\.klarna\.com/3ds'
]]

PLATFORM_KEYWORDS = {
    "woocommerce": "WooCommerce",
    "shopify": "Shopify",
    "magento": "Magento",
    "bigcommerce": "BigCommerce",
    "prestashop": "PrestaShop",
    "opencart": "OpenCart",
    "wix": "Wix",
    "squarespace": "Squarespace"
}

GRAPHQL_KEYWORDS = [re.compile(pattern, re.IGNORECASE) for pattern in [
    r'/graphql', r'graphql\.js', r'graphql-endpoint', r'query \{', r'mutation \{'
]]

# --- Detection indicators ---
INDICATOR_PATHS = ["cart", "checkout", "payment", "pay", "buy", "purchase", "order", "billing", "invoice", "transaction", "secure-checkout", "confirm-purchase", "complete-order", "place-order", "express-checkout", "quick-buy", "buy-now", "shop-now", "subscribe", "trial", "renew", "upgrade", "membership", "plans", "apply-coupon", "discount-code", "gift-card", "promo-code", "redeem-code", "payment-method", "payment-details", "payment-form", "pricing", "plans", "pricing-plan", "donate", "support", "pledge", "give"]

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
                    if self.is_relevant_url(full) and full not in self.visited:
                        urls.add(full)
                onclick = await el.get_attribute("onclick")
                if onclick:
                    matches = re.findall(r'"(https?://[^"]+|/[^"\s]+)"', onclick)
                    for m in matches:
                        full = urljoin(base_url, m)
                        if self.is_relevant_url(full) and full not in self.visited:
                            urls.add(full)
        return urls

    async def analyze_page_playwright(self, browser, url: str) -> Dict[str, Any]:
        data = {
            "gateways": set(), "captcha": set(), "three_ds": False,
            "cloudflare": False, "platform": None, "graphql": False
        }
        page = await browser.new_page()
        await page.add_init_script(path="stealth.min.js")
        try:
            await page.goto(url, timeout=30000)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)
            content = await page.content()
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
            logger.error(f"Playwright page error ({url}): {e}")
        finally:
            await page.close()
        return data

    async def playwright_worker(self, browser, queue: asyncio.Queue, results: List[Dict[str, Any]], semaphore: asyncio.Semaphore):
        while not queue.empty():
            url = await queue.get()
            if url in self.visited:
                queue.task_done()
                continue
            self.visited.add(url)
            async with semaphore:
                result = await self.analyze_page_playwright(browser, url)
                results.append(result)
            queue.task_done()

    async def playwright_scan(self, urls: Set[str], concurrency: int = 5) -> List[Dict[str, Any]]:
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

        results = []
        try:
            for url in urls:
                if url in self.visited:
                    continue
                self.visited.add(url)
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
        return result

scanner = StealthGatewayScanner()

@app.get("/scan", response_model=ScanResult)
async def scan(url: str = Query(..., description="Target website URL")):
    return await scanner.full_scan(url)
