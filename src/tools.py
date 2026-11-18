"""
Tools available to the agent, grouped in a ToolBox bound to one
AppConfig (so the allowlist and limits come from config.yaml rather
than being hardcoded). Every tool routes through _check_allowed()
first and refuses to touch anything not on config.allowed_hosts.

Tool schemas are written once in a provider-neutral JSON-schema form
and converted to each provider's format in llm_clients.py.
"""
import socket
from urllib.parse import urljoin, urlparse

import requests

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite3.operationalerror",
    "unclosed quotation mark", "pg_query", "syntax error at or near",
]


class ToolBox:
    def __init__(self, config):
        self.config = config

    # -- safety --------------------------------------------------------
    def _check_allowed(self, url_or_host: str) -> None:
        host = url_or_host.split("//")[-1].split("/")[0].split(":")[0]
        if host not in self.config.allowed_hosts:
            raise PermissionError(
                f"Refusing to act on '{host}'. Allowed hosts: "
                f"{self.config.allowed_hosts}. Add it to config.yaml only "
                "if you own/control this target."
            )

    # -- recon -----------------------------------------------------------
    def http_request(self, url: str, method: str = "GET", data: dict | None = None) -> dict:
        """Make an HTTP request to the target and return status/headers/body (truncated)."""
        self._check_allowed(url)
        resp = requests.request(method, url, data=data, timeout=5)
        return {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text[:2000]}

    def port_scan(self, host: str, ports: list | None = None) -> dict:
        """Scan a short list of common ports on the target host."""
        self._check_allowed(host)
        ports = (ports or [21, 22, 80, 443, 3000, 8080, 8443])[: self.config.max_ports_scanned]
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
            finally:
                sock.close()
        return {"host": host, "open_ports": open_ports}

    def banner_grab(self, host: str, port: int) -> dict:
        """Open a TCP connection and read whatever banner the service sends first."""
        self._check_allowed(host)
        try:
            with socket.create_connection((host, port), timeout=1.5) as sock:
                sock.settimeout(1.5)
                banner = sock.recv(256)
            return {"host": host, "port": port, "banner": banner.decode(errors="replace").strip()}
        except (OSError, socket.timeout) as e:
            return {"host": host, "port": port, "error": str(e)}

    def dir_brute(self, base_url: str, wordlist: list | None = None) -> dict:
        """Check a short list of common paths for a non-error response."""
        self._check_allowed(base_url)
        found = []
        for path in wordlist or self.config.common_paths:
            url = urljoin(base_url, path)
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code < 400:
                    found.append({"path": path, "status": resp.status_code})
            except requests.RequestException:
                continue
        return {"base_url": base_url, "found": found}

    def header_analysis(self, url: str) -> dict:
        """Flag commonly-expected security headers that are missing from the response."""
        self._check_allowed(url)
        resp = requests.get(url, timeout=5)
        present = {h.lower() for h in resp.headers.keys()}
        missing = [h for h in SECURITY_HEADERS if h not in present]
        return {"url": url, "missing_security_headers": missing, "server": resp.headers.get("Server")}

    # -- lightweight, benign vulnerability signals ------------------------
    def reflected_param_check(self, base_url: str, param: str) -> dict:
        """
        Send a unique, inert marker string as a query parameter and check
        whether it comes back unescaped in the response body — a standard,
        non-exploitative heuristic for reflected-input issues (the same
        check any passive web scanner runs; no script is ever executed).
        """
        self._check_allowed(base_url)
        marker = "reconmarker12345"
        parsed = urlparse(base_url)
        sep = "&" if parsed.query else "?"
        url = f"{base_url}{sep}{param}={marker}"
        resp = requests.get(url, timeout=5)
        reflected_raw = marker in resp.text
        return {"url": url, "param": param, "reflected_unescaped": reflected_raw}

    def sql_error_probe(self, base_url: str, param: str) -> dict:
        """
        Append a single quote to a parameter value and check the response
        for known database error signatures — a standard benign detection
        heuristic, not an injection or data-extraction attempt.
        """
        self._check_allowed(base_url)
        parsed = urlparse(base_url)
        sep = "&" if parsed.query else "?"
        url = f"{base_url}{sep}{param}='"
        resp = requests.get(url, timeout=5)
        body_lower = resp.text.lower()
        hits = [sig for sig in SQL_ERROR_SIGNATURES if sig in body_lower]
        return {"url": url, "param": param, "db_error_signatures_found": hits}

    # -- wiring for the agent loop ----------------------------------------
    def functions(self) -> dict:
        return {
            "http_request": self.http_request,
            "port_scan": self.port_scan,
            "banner_grab": self.banner_grab,
            "dir_brute": self.dir_brute,
            "header_analysis": self.header_analysis,
            "reflected_param_check": self.reflected_param_check,
            "sql_error_probe": self.sql_error_probe,
        }


TOOL_SCHEMAS = [
    {
        "name": "http_request",
        "description": "Make an HTTP request to the allowlisted target and inspect the response.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                "data": {"type": "object"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "port_scan",
        "description": "Scan a short list of common ports on the allowlisted target host.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["host"],
        },
    },
    {
        "name": "banner_grab",
        "description": "Connect to an open port on the allowlisted host and read its service banner.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "dir_brute",
        "description": "Probe a short list of common paths on the allowlisted target for accessible endpoints.",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "wordlist": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["base_url"],
        },
    },
    {
        "name": "header_analysis",
        "description": "Check an allowlisted URL's response for missing standard security headers.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "reflected_param_check",
        "description": (
            "Benign heuristic: send an inert marker value as a query parameter on the "
            "allowlisted target and check if it is reflected unescaped in the response."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["base_url", "param"],
        },
    },
    {
        "name": "sql_error_probe",
        "description": (
            "Benign heuristic: append a single quote to a query parameter on the "
            "allowlisted target and check the response for database error signatures."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["base_url", "param"],
        },
    },
]
