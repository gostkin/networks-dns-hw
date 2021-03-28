import time
import typing as tp

from DnsResponseRecord import DnsResponseRecord
from IpRecord import IpRecord

from Utils import parse_int, parse_name


class DnsResponse:
    def __init__(self, response: tp.Optional[bytes] = None) -> None:
        self.response = response
        self.request_success = response is not None

        self.request_id: int = 0
        self.a_records: tp.List[DnsResponseRecord] = []
        self.ns_records: tp.List[DnsResponseRecord] = []
        self.aaaa_records: tp.List[DnsResponseRecord] = []
        self.r_code: int = 0

        self.parsed = False
        self.parsed_success = False
        self.request_time = time.time()
        if response is not None:
            self._parse()

    def get_a_ip_record(self) -> tp.Optional[IpRecord]:
        ips: tp.List[tp.Tuple[str, str]] = []
        ttl = None
        for record in self.a_records:
            ips.append((record.domain, record.ip))
            if ttl is None:
                ttl = record.ttl
            else:
                ttl = min(record.ttl, ttl)

        if len(ips) == 0:
            return None

        return IpRecord(expires_at=self.request_time + ttl, ips=ips)

    def get_domains_and_servers(self) -> tp.Tuple[tp.List[str], tp.Dict[str, str]]:
        domains = [record.domain for record in self.ns_records]
        servers: tp.Dict[str, str] = {}
        for a_record in self.a_records:
            if a_record.domain in domains:
                servers[a_record.domain] = a_record.ip
        return domains, servers

    def _parse(self) -> None:
        if self.parsed:
            return

        self.request_id = parse_int(self.response[:2])

        params = parse_int(self.response[2:4])
        self.aa = bool(1 & (params >> 10))
        self.r_code = 0xF & params

        an_count = parse_int(self.response[6:8])
        ns_count = parse_int(self.response[8:10])
        ar_count = parse_int(self.response[10:12])

        if self.aa and self.r_code == 3:
            self.parsed = True
            self.parsed_success = False
            return

        offset = 12
        domain, bytes_handled = self._parse_request(offset)
        offset += bytes_handled
        for i in range(an_count + ns_count + ar_count):
            record, bytes_handled = self._parse_record(offset)
            offset += bytes_handled
            if record.rr_type == 1:
                self.a_records.append(record)
            elif record.rr_type == 2:
                self.ns_records.append(record)
            elif record.rr_type == 28:
                self.aaaa_records.append(record)

        self.parsed = True
        self.parsed_success = True

    def _parse_request(self, offset: int) -> (str, int):
        domain, bytes_handled = parse_name(self.response, offset)
        return domain, bytes_handled + 4

    def _parse_record(self, offset: int) -> (DnsResponseRecord, int):
        name, bytes_handled = parse_name(self.response, offset)
        record = DnsResponseRecord(response=self.response, domain=name, offset=offset + bytes_handled)
        bytes_handled += record.bytes_handled
        return record, bytes_handled
