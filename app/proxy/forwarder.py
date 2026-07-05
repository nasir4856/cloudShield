import logging
import time

import requests
from flask import Response, current_app, redirect, request

from app.models import ProtectedApplication


logger = logging.getLogger(__name__)


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

        if response.status_code == 302 and "Location" in response.headers:
            return redirect(response.headers["Location"])

        excluded_headers = {
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
        }
        response_headers = [
            (name, value)
            for name, value in response.headers.items()
            if name.lower() not in excluded_headers
        ]
        return response.content, response.status_code, response_headers
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
