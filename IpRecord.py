import typing as tp

from dataclasses import dataclass


@dataclass
class IpRecord:
    expires_at: float
    ips: tp.List[tp.Tuple[str, str]]
