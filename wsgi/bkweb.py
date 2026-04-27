# SPDX-License-Identifier: MIT

import functools
import os
import pathlib
import re
import textwrap
import urllib.request

import badkeys
from msgs import msgs


@functools.cache
def htmltop():
    htmltopfile = os.path.join(os.path.realpath(os.path.dirname(__file__)), "../tmpl/top.tmpl")
    html = pathlib.Path(htmltopfile).read_text()
    html = re.sub(r"<script src=.*></script>\n", "", html)
    html = re.sub(r"<meta property=.*>\n", "", html)
    html = html.replace("</head>", '<meta name="robots" content="noindex"></head>')
    return html.replace("_PRE_", "Results - ")


htmlbottom = "</main></body></html>"

regt = (b"-----BEGIN[A-Z ]{0,5} PRIVATE KEY-----[0-9A-Za-z/+=\n]{1,10000}?"
        b"-----END[A-Z ]{0,5} PRIVATE KEY-----")
kreg = re.compile(regt, flags=re.MULTILINE | re.DOTALL)


def printblkey(rawurl, niceurl):
    try:
        keydata = urllib.request.urlopen(rawurl).read(10000)
        k = kreg.search(keydata)
        if k:
            key = k[0].decode()
            xhtml = "<br>The private key is:<br>"
            xhtml += f"<textarea disabled='disabled' class='keyout'>{key}</textarea>"
        else:
            xhtml = "<br>We tried to get the private key, but an error occured.<br>"
            xhtml += f"Private key not found in {rawurl}<br>"
    except urllib.error.HTTPError:
        xhtml = "<br>We tried to get the private key, but an error occured.<br>"
        xhtml += f"HTTP error with {rawurl}<br>"

    xhtml += f"<br>You can find the <a href='{niceurl}'>private key here</a>."
    return xhtml


def fancyhex(i):
    h = f"{i:02x}"
    if len(h) % 2 == 1:
        h = f"0{h}"
    h = ":".join(textwrap.wrap(h, 2))
    h = "<wbr>".join(textwrap.wrap(h, 48))
    return f"<span class='mono'>{h}</span>"


@functools.cache
def getnoinput():
    return htmltop() + msgs["noinput"] + htmlbottom


def gethtml(mykey):
    warningmsgs = ""

    checks = [*badkeys.defaultchecks.keys(), "rsabias"]

    ret = badkeys.detectandcheck(mykey, checks=checks, keyrecover=True)

    myhtml = htmltop()

    if ret["type"] == "unknown":
        myhtml += "Unsupported key type"
        return myhtml
    if ret["type"] == "notfound":
        myhtml += "No key found"
        return myhtml
    if ret["type"] == "unparseable":
        myhtml += "Unparseable key"
        return myhtml

    for r, rr in ret["results"].items():
        if r == "rsabias":
            if "subtest" in rr and rr["subtest"] == "vanity":
                warningmsgs += msgs["vanity"]
            else:
                warningmsgs += msgs["rsabias"]
            continue
        myhtml += "<div class='container'>"
        myhtml += "<p class='center'>"
        myhtml += "<img src='/img/block.svg' alt='broken' width='50'><br>"

        myhtml += "This key is insecure!<br>"

        # use more specific subtest message is available, generic if not
        if "subtest" in rr and rr["subtest"] in msgs:
            myhtml += msgs[rr["subtest"]]
        elif r in msgs:
            myhtml += msgs[r]
        elif r in msgs:
            myhtml += msgs[r]
        else:
            myhtml += f"{r} vulnerability!"

        if r == "blocklist":

            if "lookup" in rr:
                niceurl, rawurl = badkeys.allkeys.urllookup(
                    rr["blid"], rr["lookup"]
                )
                if niceurl:
                    myhtml += printblkey(rawurl, niceurl)
                else:
                    myhtml += "<br>It is a new key that is not in our URL lookup database yet."

        res = ret["results"][r]
        if "privatekey" in res:
            myhtml += ("</p><p class='center'>We can calculate the private key:<br>"
                       "<textarea disabled='disabled' class='keyout'>"
                       f"{res['privatekey']}</textarea>")

        myhtml += "</p></div>"

    if ret["type"] == "rsa":
        if ret["bits"] < 2048:
            warningmsgs += msgs["below2048"]
        if (ret["bits"] % 8) != 0:
            warningmsgs += msgs["not8x"]
        elif ret["bits"] not in [512, 768, 1024, 2048, 3072, 4096, 8192]:
            warningmsgs += msgs["unusualsize"]
        if ret["e"] == 3:
            warningmsgs += msgs["exponent3"]
        elif ret["e"] != 65537:
            warningmsgs += msgs["enot65537"]

    if ret["type"] == "dsa":
        warningmsgs += msgs["dsa"]

    if warningmsgs != "":
        myhtml += "<div class='container'>"
        myhtml += "<p class='center'>"
        myhtml += "<img src='/img/warning.svg' alt='warning' width='50'><br>"
        myhtml += "There are warnings about this key.<br>"
        myhtml += warningmsgs
        myhtml += "</p></div>"

    if not ret["results"] and warningmsgs == "":
        myhtml += "<p class='center'>"
        myhtml += "<img src='/img/ok.svg' alt='OK' width='50'><br>"
        myhtml += "This key is not affected by any of the vulnerabilities that we can detect!<br>"
        myhtml += "</p>"

    if ret["type"] == "rsa":
        myhtml += "<table><tr><td>key type</td><td>RSA</td></tr>"
        myhtml += f"<tr><td>bits</td><td>{ret['bits']}</td></tr>"
        myhtml += f"<tr><td>e</td><td>{fancyhex(ret['e'])}"
        if ret["e"] < 100000:
            myhtml += f" (decimal {ret['e']})"
        myhtml += "</td></tr>"
        myhtml += f"<tr><td>N</td><td>{fancyhex(ret['n'])}"
    elif ret["type"] == "ec":
        myhtml += "<table><tr><td>key type</td><td>Elliptic Curve</td></tr>"
        if isinstance(ret["x"], int):
            myhtml += f"<tr><td>x coordinate</td><td>{fancyhex(ret['x'])}"
    elif ret["type"] == "dsa":
        myhtml += "<table><tr><td>key type</td><td>DSA</td></tr>"
    else:
        myhtml += f"<table><tr><td>key type</td><td>{ret['type']}</td></tr>"

    if "spkisha256" in ret:
        myhtml += "<tr><td>SPKI&nbsp;SHA256<br><span class='small'>"
        myhtml += f"(<a href='https://crt.sh?spkisha256={ret['spkisha256']}'>search on crt.sh</a>)"
        myhtml += f"</span></td><td>{ret['spkisha256']}</td></tr>"
    myhtml += "</table>"

    myhtml += htmlbottom

    return myhtml
