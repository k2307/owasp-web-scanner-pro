import asyncio
from scanner.modules import (
    access_control,
    misconfig,
    integrity,
    crypto,
    injection,
    ssrf
)

class ScannerEngine:
    def __init__(self, target):
        self.target = target
        self.issues = []

    async def run_all(self):
        tasks = [
            access_control.scan(self.target),
            misconfig.scan(self.target),
            integrity.scan(self.target),
            crypto.scan(self.target),
            injection.scan(self.target),
            ssrf.scan(self.target)
        ]

        results = await asyncio.gather(*tasks)

        for result in results:
            self.issues.extend(result)

        return self.issues
