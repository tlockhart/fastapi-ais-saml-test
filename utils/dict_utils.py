def _deep_merge(target: dict, overrides: dict) -> None:
    """
    Recursively merge `overrides` into `target` in-place.
    Nested dicts are merged rather than overwritten.
    """
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        else:
            target[key] = value
