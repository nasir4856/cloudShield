import logging
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from flask import Response, current_app, redirect, request

from app.models import ProtectedApplication


logger = logging.getLogger(__name__)
HTML_URL_ATTRIBUTES = ("href", "src", "action")


def forward_request(
    application: ProtectedApplication,
    upstream_path: str | None = None,
) -> Response | tuple[bytes, int, list[tuple[str, str]]]:
    target_url = (
        f"{application.upstream_url.rstrip('/')}/{upstream_path}"
        if upstream_path
        else application.upstream_url.rstrip("/")
    )
    headers = {
        key: value
        for key, value in request.headers
        if key.lower() not in {"host", "content-length"}
    }
    start_time = time.perf_counter()
    logger.info(
        "Selected application=%s public_path=%s proxy_target=%s",
        application.name,
        application.public_path,
        target_url,
    )

    try:
        response = requests.request(
            request.method,
            target_url,
            headers=headers,
            params=request.args,
            data=request.get_data() if request.method != "GET" else None,
            cookies=request.cookies,
            timeout=current_app.config["UPSTREAM_TIMEOUT"],
            allow_redirects=False,
        )
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "Proxy response application=%s status_code=%s response_time_ms=%s",
            application.name,
            response.status_code,
            elapsed_ms,
        )

        if response.is_redirect and "Location" in response.headers:
            return redirect(_rewrite_redirect_location(application, response.headers["Location"]))

        excluded_headers = {
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
        }
        body = response.content
        response_headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in excluded_headers
        ]
        if _is_html_response(response):
            body = _rewrite_html_body(response, application)

        return body, response.status_code, response_headers
    except requests.ConnectionError:
        logger.exception("Failed to connect to upstream application %s.", application.name)
        return Response(
            '{"error": "Upstream application is unreachable"}',
            502,
            mimetype="application/json",
        )
    except requests.Timeout:
        logger.exception("Upstream application %s timed out.", application.name)
        return Response(
            '{"error": "Upstream application timed out"}',
            502,
            mimetype="application/json",
        )
    except requests.RequestException:
        logger.exception("Unexpected proxy request error.")
        return Response(
            '{"error": "Proxy request failed"}',
            502,
            mimetype="application/json",
        )


def _is_html_response(response: requests.Response) -> bool:
    return "text/html" in response.headers.get("Content-Type", "").lower()


def _rewrite_redirect_location(application: ProtectedApplication, location: str) -> str:
    upstream_base = application.upstream_url.rstrip("/")
    public_path = application.public_path.rstrip("/") or "/"
    parsed_location = urlparse(location)

    if parsed_location.scheme and location.startswith(upstream_base):
        suffix = location[len(upstream_base) :].lstrip("/")
        return f"{public_path}/{suffix}" if suffix else public_path

    if location.startswith("/") and not location.startswith("//"):
        return _with_public_path(public_path, location)

    return location


def _rewrite_html_body(
    response: requests.Response,
    application: ProtectedApplication,
) -> bytes:
    public_path = application.public_path.rstrip("/") or "/"
    if public_path == "/":
        return response.content

    encoding = response.encoding or "utf-8"
    html = response.text

    for attribute in HTML_URL_ATTRIBUTES:
        html = re.sub(
            rf'({attribute}\s*=\s*["\'])(/[^/"\'][^"\']*)',
            lambda match: (
                f"{match.group(1)}{_with_public_path(public_path, match.group(2))}"
            ),
            html,
            flags=re.IGNORECASE,
        )

    html = re.sub(
        r'(url\(\s*["\']?)(/[^/)"\'][^)"\']*)',
        lambda match: (
            f"{match.group(1)}{_with_public_path(public_path, match.group(2))}"
        ),
        html,
        flags=re.IGNORECASE,
    )

    return html.encode(encoding, errors="replace")


def _with_public_path(public_path: str, target_path: str) -> str:
    if target_path == public_path or target_path.startswith(f"{public_path}/"):
        return target_path
    return urljoin(f"{public_path}/", target_path.lstrip("/"))
