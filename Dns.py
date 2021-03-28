import typing as tp
import socket

from DnsResponse import DnsResponse
from IpRecord import IpRecord
from Trace import Trace

ROOT_SERVERS_DNS = {
    "a.root-servers.net": '198.41.0.4',
    "b.root-servers.net": '199.9.14.201',
    "c.root-servers.net": '192.33.4.12',
    "d.root-servers.net": '199.7.91.13',
    "e.root-servers.net": '192.203.230.10',
    "f.root-servers.net": '192.5.5.241',
    "g.root-servers.net": '192.112.36.4',
    "h.root-servers.net": '198.97.190.53',
    "i.root-servers.net": '192.36.148.17',
    "j.root-servers.net": '192.58.128.30',
    "k.root-servers.net": '193.0.14.129',
    "l.root-servers.net": '199.7.83.42',
    "m.root-servers.net": '202.12.27.33',
}


def find_recursive(
    domain: str,
    dns_servers: tp.Dict[str, str],
    trace: Trace
) -> tp.Optional[IpRecord]:
    for server_domain, host in dns_servers.items():
        trace.add(f"{host} {server_domain}")
        response = create_and_send_request(domain, host)
        if not response.request_success or not response.parsed_success:
            continue

        if response.aa:
            return response.get_a_ip_record()

        domains, servers = response.get_domains_and_servers()

        if len(servers) == 0 and len(domains) != 0:
            new_domain = domains[0]
            result = find_recursive(new_domain, ROOT_SERVERS_DNS, trace)
            if result:
                dns_servers = {new_domain: ip for _, ip in result.ips}
                return find_recursive(domain, dns_servers, trace)
        else:
            return find_recursive(domain, servers, trace)
    return None


def create_and_send_request(domain: str, ip: str) -> DnsResponse:
    request = create_request(domain=domain, request_id=228)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(request, (ip, 53))
            response = DnsResponse(s.recvfrom(4096)[0])
    except Exception as e:
        print(e)
        return DnsResponse()

    # print(vars(response))
    # for res in response.a_records:
    #     print(vars(res))
    return response


def create_request(domain: str, request_id: int) -> bytes:
    parameters = bytearray()
    parameters.extend(request_id.to_bytes(2, byteorder='big', signed=False))

    zero = 0
    parameters.extend(zero.to_bytes(2, byteorder='big', signed=False))

    questions = 1
    parameters.extend(questions.to_bytes(2, byteorder='big', signed=False))

    parameters.extend(zero.to_bytes(6, byteorder='big', signed=False))

    parts = domain.split(".")
    if len(parts[-1]) == 0:
        parts.pop()

    for part in parts:
        part_len = len(part)
        if part_len > 255:
            raise OverflowError
        parameters.extend(part_len.to_bytes(1, byteorder='big', signed=False))
        parameters.extend(bytes(part, encoding="ascii"))

    parameters.extend(zero.to_bytes(1, byteorder='big', signed=False))

    q_type = 1
    parameters.extend(q_type.to_bytes(2, byteorder='big', signed=False))

    q_class = 1
    parameters.extend(q_class.to_bytes(2, byteorder='big', signed=False))
    return bytes(parameters)
