# SPDX-License-Identifier: MIT

import urllib.parse

from bkweb import gethtml


def application(environ, start_response):
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/html"),
            (
                "Content-Security-Policy",
                "default-src 'none';script-src 'self';style-src 'self';img-src 'self';upgrade-insecure-requests;frame-ancestors 'none';base-uri 'self';form-action 'self'",
            ),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ],
    )
    request_body = environ["wsgi.input"].read()
    d = urllib.parse.parse_qs(request_body.decode())
    try:
        inkey = d["inkey"][0]
    except KeyError:
        return [b"No input"]
    html = gethtml(inkey)
    return [html.encode()]
