"""Runtime proof that the symbol-fetcher has no direct outbound path.

This script is intended to be run from inside the symbol-fetcher
container.  Each test is expected to FAIL (i.e. block the connection)
except the last one which connects to the internal gateway.

NEVER run this in production.  It performs no destructive operations
but it does open sockets to the configured targets.
"""
import socket
import sys
import urllib.request
import urllib.error


def attempt(name: str, fn) -> bool:
    try:
        result = fn()
    except Exception as exc:
        print(f"PASS  {name}: blocked ({type(exc).__name__})")
        return True
    print(f"FAIL  {name}: unexpectedly succeeded -> {result!r}")
    return False


def main() -> int:
    failures = 0
    # 1. Direct HTTPS to a public IP.
    def test_public_ip():
        s = socket.socket()
        s.settimeout(5)
        s.connect(("8.8.8.8", 443))
        s.close()
        return True
    if not attempt("direct public IP 8.8.8.8:443", test_public_ip):
        failures += 1

    # 2. Direct HTTPS to msdl.microsoft.com.
    def test_msdl():
        s = socket.socket()
        s.settimeout(5)
        s.connect(("msdl.microsoft.com", 443))
        s.close()
        return True
    if not attempt("direct msdl.microsoft.com:443", test_msdl):
        failures += 1

    # 3. Direct HTTPS to 1.1.1.1.
    def test_cloudflare():
        s = socket.socket()
        s.settimeout(5)
        s.connect(("1.1.1.1", 443))
        s.close()
        return True
    if not attempt("direct 1.1.1.1:443", test_cloudflare):
        failures += 1

    # 4. curl/wget-style HTTP request (urllib).
    def test_urllib():
        urllib.request.urlopen("https://example.com/", timeout=5).read()
        return True
    if not attempt("urllib https://example.com/", test_urllib):
        failures += 1

    # 5. Private metadata endpoint.
    def test_metadata():
        s = socket.socket()
        s.settimeout(5)
        s.connect(("169.254.169.254", 80))
        s.close()
        return True
    if not attempt("AWS metadata 169.254.169.254:80", test_metadata):
        failures += 1

    # 7. Internal gateway reachability: this MUST succeed.
    def test_gateway():
        s = socket.socket()
        s.settimeout(5)
        s.connect(("symbol-egress-gateway", 8443))
        s.close()
        return True
    try:
        result = test_gateway()
    except Exception as exc:
        print(f"FAIL  internal gateway symbol-egress-gateway:8443 unexpectedly blocked ({type(exc).__name__})")
        failures += 1
    else:
        print(f"PASS  internal gateway symbol-egress-gateway:8443 reachable")

    if failures:
        print(f"\nFAILED {failures} direct egress test(s).")
        return 1
    print("\nAll direct egress blocked.  Internal gateway reachable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
