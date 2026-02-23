import importlib
import pkgutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def load_plugins(
    enabled_modules=None,
    disabled_modules=None,
    strict=False
):
    """
    Load scanner modules dynamically.

    Args:
        enabled_modules (set|list|None):
            Modules explicitly enabled.
            None = load all.
        disabled_modules (set|list|None):
            Modules to skip.
        strict (bool):
            If True, raise errors on load failure.

    Returns:
        list[dict]:
            [
                {
                    "name": "injection",
                    "module": module_obj,
                    "loaded": True
                }
            ]
    """

    enabled_modules = set(enabled_modules or [])
    disabled_modules = set(disabled_modules or [])

    loaded_plugins = []

    modules_path = Path(__file__).parent.parent / "modules"

    for _, name, _ in pkgutil.iter_modules([str(modules_path)]):

        # Skip private files
        if name.startswith("_"):
            continue

        # Respect enabled list
        if enabled_modules and name not in enabled_modules:
            continue

        # Respect disabled list
        if name in disabled_modules:
            logger.info(f"[PLUGIN] Skipped (disabled): {name}")
            continue

        module_path = f"scanner.modules.{name}"

        try:
            module = importlib.import_module(module_path)

            # Validate module interface
            if not hasattr(module, "scan"):
                logger.warning(
                    f"[PLUGIN] {name} skipped (missing async scan function)"
                )
                continue

            loaded_plugins.append({
                "name": name,
                "module": module,
                "loaded": True
            })

            logger.info(f"[PLUGIN] Loaded: {name}")

        except Exception as e:
            logger.error(f"[PLUGIN] Failed loading {name}: {e}")

            if strict:
                raise

    return loaded_plugins