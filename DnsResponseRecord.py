import ipaddress

from Utils import parse_int, parse_name


class DnsResponseRecord:
    def __init__(self, domain: str, response: bytes, offset: int):
        self.domain = domain.lower()
        self.rr_type: int = 0
        self.ttl: int = 0
        self.ip: str = ""

        bytes_handled = 0
        self.rr_type = parse_int(response[offset + bytes_handled: offset + bytes_handled + 2])
        bytes_handled += 4
        self.ttl = parse_int(response[offset + bytes_handled + 2: offset + bytes_handled + 4])
        bytes_handled += 4
        rd_length = parse_int(response[offset + bytes_handled: offset + bytes_handled + 2])
        bytes_handled += 2
        rdata = response[offset + bytes_handled: offset + bytes_handled + rd_length]

        if self.rr_type == 1:  # A
            self.ip = str(ipaddress.ip_address(parse_int(rdata)))
            bytes_handled += 4
        elif self.rr_type == 2:  # NS
            self.domain, handled = parse_name(response, offset + bytes_handled)
            assert handled == rd_length
            bytes_handled += handled
        elif self.rr_type == 28:  # ipv6
            assert len(rdata) == 16
            self.ip = str(ipaddress.ip_address(parse_int(rdata)))
            bytes_handled += 16
        else:
            bytes_handled += len(rdata)

        self.bytes_handled = bytes_handled
