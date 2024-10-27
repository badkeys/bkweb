import re
import textwrap
import urllib.request

import badkeys
import rsatool


def printblkey(rawurl, niceurl):
    xhtml = ""
    try:
        keystring = urllib.request.urlopen(rawurl).read().decode()
        # do some validation to prevent XSS via the key repos
        if re.fullmatch(r"^[A-Za-z0-9/+= \n-]*$", keystring, re.MULTILINE):
            xhtml += "<br>The private key is:<br>"
            xhtml += (
                f"<textarea disabled='disabled' class='keyout'>{keystring}</textarea>"
            )
    except urllib.error.HTTPError:
        xhtml += "<br>We tried to get the private key, but an error occured.<br>"
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

        myhtml += "This key is broken!<br>"
        if r == "fermat":
            if "subtest" in rr and rr["subtest"] == "square":
                myhtml += 'This is a "square" RSA key (broken)'
            else:
                myhtml += "<a href='/docs/fermat.html'>"
                myhtml += "Fermat Attack (CVE-2022-26320)"
                myhtml += "</a>"
        elif r == "roca":
            myhtml += "<a href='/docs/roca.html'>Return of Coopersmith's Attack / ROCA (CVE-2017-15361)</a>"
        elif r == "blocklist":
            if rr["subtest"] == "debianssl":
                myhtml += (
                    "<a href='/docs/debian.html'>Debian OpenSSL bug (CVE-2008-0166)</a>"
                )
            elif rr["subtest"] == "keypair":
                myhtml += "<a href='/docs/keypair.html'>keypair/Gitkraken bug (CVE-2021-41117)</a>"
            elif rr["subtest"] == "documentation":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is used in documentation as an example.</a>"
            elif rr["subtest"] == "firmware":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is a static key from a device firmware.</a>"
            elif rr["subtest"] == "localhostcert":
                myhtml += "<a href='/docs/publicprivate.html'>The private key was used for a localhost certificate.</a>"
            elif rr["subtest"] == "localroot":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is a static key installed by a software root certificate.</a>"
            elif rr["subtest"] == "misc":
                myhtml += '<a href="/docs/publicprivate.html">The private key can be found in the "Kompromat" repository.</a>'
            elif rr["subtest"] == "rfc":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is part of an IETF RFC or draft document.</a>"
            elif rr["subtest"] == "softwaretests":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is used in a software test suite.</a>"
            elif rr["subtest"] == "testvectors":
                myhtml += "<a href='/docs/publicprivate.html'>The private key is used as a test vector in a cryptographic test suite.</a>"
            else:
                myhtml += "<a href='/docs/publicprivate.html'>The private key is in one of our blocklists.</a>"

            if "lookup" in rr:
                lookup = badkeys.allkeys.urllookup(
                    rr["blid"], rr["lookup"], type="both"
                )
                if lookup:
                    niceurl, rawurl = lookup
                    myhtml += printblkey(rawurl, niceurl)
                else:
                    myhtml += "<br>It is a new key that is not in our URL lookup database yet."

        elif r == "sharedprimes":
            myhtml += "This RSA key has a <a href='/docs/commonprimes.html'>common prime factor</a> with another key.<br>This allows breaking the private key by calculating the GCD."
        elif r == "smallfactors":
            myhtml += "This RSA key has small prime factors.<br>This is usually a sign of data corruption in the key."
        elif r == "pattern":
            myhtml += "The key contains an implausible repeating pattern that indicates non-random prime factors."

        else:
            myhtml += f"{r} vulnerability!"

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
            warningmsgs += "<a href='/docs/keysize.html'>RSA keys smaller than 2048 bits are considered insecure.</a><br>"
        if (ret["bits"] % 8) != 0:
            warningmsgs += "<a href='/docs/keysize.html'>This RSA key has a very unusual key size that is not a multiple of 8.<br>This can cause compatibility issues.</a><br>"
        elif ret["bits"] not in [512, 768, 1024, 2048, 3072, 4096, 8192]:
            warningmsgs += "<a href='/docs/keysize.html'>This RSA key has an unusual key size.</a><br>"
        if ret["e"] == 3:
            warningmsgs += "<a href='/docs/exponent.html'>RSA exponent 3 is discouraged, it enables some attacks.</a><br>"
        elif ret["e"] != 65537:
            warningmsgs += "<a href='/docs/exponent.html'>RSA exponent is not the recommended default value (e = 65537).</a><br>"

    if ret["type"] == "dsa":
        warningmsgs += (
            "<a href='/docs/dsa.html'>DSA keys are not recommended any more.</a>"
        )

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
