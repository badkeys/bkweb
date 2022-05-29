import urllib.parse

from bkweb import gethtml


def application(environ, start_response):
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
        ],
    )
    request_body = environ["wsgi.input"].read()
    d = urllib.parse.parse_qs(request_body.decode())
    try:
        inkey = d["inkey"][0]
    except KeyError:
        return ["No input".encode()]
    html = gethtml(inkey)
    return [html.encode()]
