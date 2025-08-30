# SPDX-License-Identifier: MIT

import re
import textwrap
import urllib.request

import badkeys
import rsatool
from msgs import msgs

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


def gethtml(mykey):
    warningmsgs = ""
    htmltop = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Results - badkeys.info</title>
<link rel="stylesheet" href="/css/milligreen.min.css">
<link rel="stylesheet" href="/css/bk.css">
</head><body>
<div class='navbar top'>
<div class="container"><div class="right">
<a href="/">Home</a> <a href="/about.html">About</a>
</div><h3><a href="/">badkeys.info</a></h3>
<p>Checking cryptographic public keys for known vulnerabilities</p>
</div></div><div><br><div class="container">"""

    ret = badkeys.detectandcheck(mykey)

    myhtml = htmltop

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
        if "p" in res and "q" in res:
            try:
                privkey = rsatool.RSA(p=res["p"], q=res["q"]).to_pem().decode()
                myhtml += "<p class='center'>We can calculate the private key:<br>"
                myhtml += f"<textarea disabled='disabled' class='keyout'>{privkey}</textarea></p>"
            except (AssertionError, ZeroDivisionError):
                # ZeroDivisionError happens with "square" RSA keys
                pass

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
        warningmsgs += "dsa"

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
    myhtml += "</table></div></div>"

    return myhtml
