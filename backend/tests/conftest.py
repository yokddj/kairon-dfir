import os

def pytest_configure():
    os.environ.setdefault("KAIRON_AUTH_ENABLED", "false")
