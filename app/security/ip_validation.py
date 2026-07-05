import ipaddress


def is_valid_ip(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return True

