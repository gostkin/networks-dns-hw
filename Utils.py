import typing as tp


def parse_name(response: bytes, offset: int) -> tp.Tuple[str, int]:
    name = ""
    processed_bytes = 0
    add_bytes_for_name = True

    while True:
        length = parse_int(response[offset: offset + 1])
        if (length & 0xC0) != 0xC0:
            offset += 1
            if add_bytes_for_name:
                processed_bytes += 1
        else:
            offset = parse_int(response[offset: offset + 2])
            offset ^= 0xC000
            if add_bytes_for_name:
                processed_bytes += 2
            add_bytes_for_name = False
            continue

        if length == 0:
            break

        name += response[offset:offset + length].decode(encoding='ascii') + "."
        offset += length
        if add_bytes_for_name:
            processed_bytes += length

    return name.lower(), processed_bytes


def parse_int(data: bytes) -> int:
    return int.from_bytes(data, 'big')
