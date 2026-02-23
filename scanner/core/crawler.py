import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag

SKIP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:")

class Crawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        concurrency: int = 10,
        include_query: bool = False
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.include_query = include_query

        self.base_netloc = urlparse(self.base_url).netloc
        self.visited = set()
        self.discovered = set()

        self._sem = asyncio.Semaphore(concurrency)

    def _normalize(self, url: str) -> str:
        # Remove fragments (#something)
        url, _ = urldefrag(url)

        p = urlparse(url)

        # Drop query params if include_query=False (prevents infinite crawl loops)
        if not self.include_query:
            p = p._replace(query="")

        # Normalize trailing slash (keep consistent)
        norm = p.geturl().rstrip("/")
        return norm

    def _is_valid_internal(self, url: str) -> bool:
        if not url or url.startswith(SKIP_SCHEMES):
            return False
        p = urlparse(url)
        if not p.scheme.startswith("http"):
            return False
        return p.netloc == self.base_netloc

    async def crawl(self):
        timeout = aiohttp.ClientTimeout(total=12)
        headers = {"User-Agent": "OWASP-Web-Scanner-Pro/1.0"}

        queue = asyncio.Queue()
        start = self._normalize(self.base_url)
        await queue.put((start, 0))
        self.discovered.add(start)

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            workers = [
                asyncio.create_task(self._worker(session, queue))
                for _ in range(self.concurrency)
            ]
            await queue.join()

            for w in workers:
                w.cancel()

        return sorted(self.discovered)

    async def _worker(self, session: aiohttp.ClientSession, queue: asyncio.Queue):
        while True:
            url, depth = await queue.get()
            try:
                await self._fetch_and_extract(session, queue, url, depth)
            finally:
                queue.task_done()

    async def _fetch_and_extract(self, session, queue, url: str, depth: int):
        if depth > self.max_depth:
            return

        url = self._normalize(url)

        if url in self.visited:
            return
        self.visited.add(url)

        async with self._sem:
            try:
                async with session.get(url, allow_redirects=True) as r:
                    ctype = (r.headers.get("Content-Type") or "").lower()
                    if "text/html" not in ctype:
                        return

                    html = await r.text(errors="ignore")

            except aiohttp.ClientError:
                return
            except Exception:
                return

        soup = BeautifulSoup(html, "html.parser")

        # -------------------------
        # Extract from multiple tags
        # -------------------------
        candidates = []

        # <a href="">
        for a in soup.find_all("a", href=True):
            candidates.append(a["href"])

        # <form action="">
        for f in soup.find_all("form", action=True):
            candidates.append(f["action"])

        # <script src="">
        for s in soup.find_all("script", src=True):
            candidates.append(s["src"])

        # <link href=""> (css, icons)
        for l in soup.find_all("link", href=True):
            candidates.append(l["href"])

        for raw in candidates:
            if not raw or raw.startswith(SKIP_SCHEMES):
                continue

            absolute = urljoin(url + "/", raw)
            absolute = self._normalize(absolute)

            if not self._is_valid_internal(absolute):
                continue

            if absolute not in self.discovered:
                self.discovered.add(absolute)
                await queue.put((absolute, depth + 1))