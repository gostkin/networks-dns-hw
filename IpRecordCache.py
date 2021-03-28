import time
import typing as tp

from collections import OrderedDict

from IpRecord import IpRecord


class IpRecordCache(object):
    def __init__(self, records_to_cache: int) -> None:
        self.records_to_cache = records_to_cache
        self.storage = OrderedDict()

    def _full(self) -> bool:
        return len(self.storage) >= self.records_to_cache

    # TODO: take ttl into account
    def _remove_one(self) -> None:
        self.storage.popitem(last=False)

    def __setitem__(self, domain: str, record: IpRecord) -> None:
        if domain in self.storage.keys():
            self.storage.move_to_end(domain)
        elif self._full():
            self._remove_one()
        self.storage[domain] = record

    def __getitem__(self, domain: str) -> tp.Optional[IpRecord]:
        try:
            record = self.storage[domain]
        except KeyError:
            return None
        if record.expires_at < time.time():
            self.storage.pop(domain)
            return None
        self.storage.move_to_end(domain)
        return record

    def __delitem__(self, domain: str) -> None:
        self.storage.pop(domain)

    def __len__(self) -> int:
        return len(self.storage)
