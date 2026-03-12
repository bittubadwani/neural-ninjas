import socket


COMMON_SUBDOMAINS = [
    "www",
    "api",
    "mail",
    "vpn",
    "portal",
    "login",
    "gateway",
    "payments",
    "secure",
    "mobile",
    "app",
]


def discover_subdomains(domain):

    discovered = []

    for sub in COMMON_SUBDOMAINS:

        full_domain = f"{sub}.{domain}"

        try:
            socket.gethostbyname(full_domain)
            discovered.append(full_domain)
        except:
            pass

    return discovered
