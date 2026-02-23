from dataclasses import dataclass, field
from typing import Set, Optional


@dataclass(frozen=True)
class Profile:
    name: str = "normal"

    # Crawl controls
    depth: int = 2
    max_pages: int = 200
    include_query: bool = False

    # Performance controls
    rate_per_sec: int = 5
    concurrency: int = 10

    # Safety controls
    request_timeout_sec: int = 12
    module_timeout_sec: int = 30

    # Plugin controls
    enabled_modules: Optional[Set[str]] = None
    disabled_modules: Set[str] = field(default_factory=set)


def get_profile(name: str) -> Profile:
    n = (name or "normal").strip().lower()

    if n == "fast":
        return Profile(
            name="fast",
            depth=1,
            max_pages=60,
            include_query=False,
            rate_per_sec=2,
            concurrency=5,
            request_timeout_sec=10,
            module_timeout_sec=20,
            enabled_modules={
                "security_headers",
                "crypto",
                "version_disclosure",
                "http_methods",
                "directory_listing",
                "waf_detection",
            },
        )

    if n == "aggressive":
        return Profile(
            name="aggressive",
            depth=4,
            max_pages=600,
            include_query=True,  # can explode; only in aggressive
            rate_per_sec=10,
            concurrency=20,
            request_timeout_sec=15,
            module_timeout_sec=45,
            # Aggressive: load most things
            enabled_modules=None,  # None = load all discovered modules
            disabled_modules=set(),  # put risky/noisy modules here if needed
        )

    # default normal
    return Profile(
        name="normal",
        depth=2,
        max_pages=200,
        include_query=False,
        rate_per_sec=5,
        concurrency=10,
        request_timeout_sec=12,
        module_timeout_sec=30,
        enabled_modules=None,
        disabled_modules=set(),
    )