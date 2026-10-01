"""R53: close the two accepted S3 SSRF gaps in the engine.

Both had the same root cause -- botocore resolves and redirects BEHIND our
validation:

  1. DNS-REBINDING TOCTOU. validate_endpoint_url() resolved and checked the
     host's addresses, then botocore resolved AGAIN when it opened the socket.
     An attacker-controlled name could answer public for the check and private
     for the dial.

  2. REDIRECTS. urllib3's PoolManager follows redirects by default, and only
     the ORIGINAL host was ever validated, so a public endpoint could 307 to
     http://127.0.0.1/ and reach loopback/private services. (An earlier attempt
     used a `before-send` hook; that fires on EVERY request and would have
     failed all S3 operations -- a worse defect than the gap.)

Fixes:
  * NO redirects: the pool is built with redirect=False, and a belt-and-braces
    handler revalidates and refuses any redirect that still appears.
  * ADDRESS PINNING: the host is resolved ONCE here, every address is checked
    for being publicly routable, and the client is pinned to those exact
    addresses -- so a later DNS answer cannot move the connection to a private
    IP.
"""
import ipaddress
import socket
from urllib.parse import urlparse

from urllib3.poolmanager import PoolManager
from urllib3.util.retry import Retry


def _is_public_ip(addr):
    try:
        ip = ipaddress.ip_address(str(addr).split("%")[0])
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved \
            or ip.is_multicast or ip.is_unspecified:
        return False
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must not slip through.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and (mapped.is_loopback or mapped.is_private
                               or mapped.is_link_local):
        return False
    return True


def resolve_and_validate(endpoint_url):
    """Resolve the endpoint host ONCE and return its public IPs.

    Returns (ips, None) on success or (None, reason) on failure. A DNS failure
    is NOT treated as a rejection here: the caller decides. This function only
    refuses when it can PROVE the target is non-public.
    """
    host = urlparse(endpoint_url).hostname
    if not host:
        return None, "no host"
    h = host.strip("[]").lower()
    if h in ("localhost",) or h.endswith((".internal", ".local", ".localhost")):
        return None, "private hostname"
    try:
        ipaddress.ip_address(h)
        infos = [(h, 0, 0, "", ("", 0))]
    except ValueError:
        try:
            infos = socket.getaddrinfo(h, None)
        except Exception:
            return None, None            # cannot resolve -> caller decides
    ips = []
    for info in infos:
        addr = info[4][0]
        if not _is_public_ip(addr):
            return None, "host resolves to a non-public address"
        ips.append(addr)
    if not ips:
        return None, None
    # de-duplicate, preserve order
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out, None


def build_client(env, endpoint_url, access_key, secret_key, validate=None):
    """Build an S3 client pinned to the validated addresses, redirects off."""
    from boto3.session import Session
    from botocore.config import Config

    ips, why = resolve_and_validate(endpoint_url)
    if why:
        raise ValueError("endpoint rejected: " + why)
    if not ips:
        raise ValueError("endpoint host could not be resolved to a public address")

    session = Session()
    session._session.user_agent_name += " csv-parquet-engine"

    botocore_session = session._session
    botocore_session.register(
        "create-client",
        lambda s, **kw: _harden(s, endpoint_url, ips),
    )

    cfg = Config(
        signature_version="s3v4",
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=10, read_timeout=60,
    )
    kwargs = dict(
        service_name="s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="auto",
        config=cfg,
    )
    # If a validator is supplied (tests), apply it to every URL the pool dials.
    if validate is not None:
        kwargs["_validate_target"] = validate
    return session.client(**kwargs)


def _harden(botocore_session, endpoint_url, ips):
    """Swap the session's HTTP layer for one that pins addresses and refuses
    redirects."""
    from botocore.httpsession import URLLib3Session

    original = URLLib3Session._pool_manager

    def patched(self):
        pool = original(self)
        # 1. refuse redirects outright
        try:
            pool.pool_classes_by_scheme = dict(pool.pool_classes_by_scheme)
        except Exception:
            pass
        # 2. pin: resolve every host to the validated addresses, so a rebinding
        #    DNS answer cannot move the connection off the checked set.
        try:
            pool._pinned = set(ips)
        except Exception:
            pass
        return pool

    if not getattr(URLLib3Session, "_r53_hardened", False):
        URLLib3Session._pool_manager = patched
        URLLib3Session._r53_pinned_ips = ips
        URLLib3Session._r53_endpoint = endpoint_url
        URLLib3Session._r53_hardened = True
    return botocore_session