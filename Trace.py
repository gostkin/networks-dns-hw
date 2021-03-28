import typing as tp


class Trace(object):
    def __init__(self):
        self.items: tp.List[str] = []

    def add(self, what: str) -> None:
        self.items.append(what)

    def compose(self) -> str:
        return "\n".join(self.items)
