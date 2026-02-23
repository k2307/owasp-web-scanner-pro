"""
OWASP Web Scanner Modules Package
Each module must expose an async function:

    async def scan(target: str) -> List[Dict]

The engine dynamically discovers and loads modules.
"""