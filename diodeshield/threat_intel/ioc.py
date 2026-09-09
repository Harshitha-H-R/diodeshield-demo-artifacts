class LocalIOCStore:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}

    def add(self, indicator: str, values: dict | None = None) -> None:
        self.items[indicator] = values or {}

    def lookup(self, indicator: str) -> dict:
        return self.items.get(indicator, {"match": False})
