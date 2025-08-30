# SPDX-License-Identifier: MIT

msgs = {
    "forti": "<a href='/docs/forti.html'>Fortigate leak (CVE-2022-40684)</a>",
    "fermat": "<a href='/docs/fermat.html'>Fermat Attack (CVE-2022-26320)</a>",
    "square": 'This is a "square" RSA key (defect)',
    "roca": "<a href='/docs/roca.html'>Return of Coopersmith's Attack / ROCA (CVE-2017-15361)</a>",
    "sharedprimes": (
        "This RSA key has a <a href='/docs/commonprimes.html'>common prime factor</a> with another"
        " key.<br>This allows breaking the private key by calculating the GCD."
    ),
    "smallfactors": (
        "This RSA key has small prime factors. This is usually an indication of data corruption.",
    ),
    "debianssl": "<a href='/docs/debian.html'>Debian OpenSSL bug (CVE-2008-0166)</a>",
    "keypair": "<a href='/docs/keypair.html'>keypair/Gitkraken bug (CVE-2021-41117)</a>",
    "documentation": (
        "<a href='/docs/publicprivate.html'>The private key is used in documentation as an"
        " example.</a>"
    ),
    "firmware": (
        "<a href='/docs/publicprivate.html'>The private key is a static key from a device"
        " firmware.</a>"
    ),
    "localhostcert": (
        "<a href='/docs/publicprivate.html'>The private key was used for a localhost"
        " certificate.</a>"
    ),
    "localroot": (
        "<a href='/docs/publicprivate.html'>The private key is a static key installed by a software"
        " root certificate.</a>"
    ),
    "misc": (
        '<a href="/docs/publicprivate.html">The private key can be found in the "Kompromat"'
        " repository.</a>"
    ),
    "rfc": (
        "<a href='/docs/publicprivate.html'>The private key is part of an IETF RFC or draft"
        " document.</a>"
    ),
    "softwaretests": (
        "<a href='/docs/publicprivate.html'>The private key is used in a software test suite.</a>"
    ),
    "testvectors": (
        "<a href='/docs/publicprivate.html'>The private key is used as a test vector in a"
        " cryptographic test suite.</a>"
    ),
    "blocklist": (
        "<a href='/docs/publicprivate.html'>The private key is in one of our blocklists.</a>"
    ),
    "below2048": (
        "<a href='/docs/keysize.html'>RSA keys smaller than 2048 bits are considered"
        " insecure.</a><br>"
    ),
    "not8x": (
        "<a href='/docs/keysize.html'>This RSA key has a very unusual key size that is not a"
        " multiple of 8.<br>This can cause compatibility issues.</a><br>"
    ),
    "unusualsize": "<a href='/docs/keysize.html'>This RSA key has an unusual key size.</a><br>",
    "exponent3": (
        "<a href='/docs/exponent.html'>RSA exponent 3 is discouraged, it enables some"
        " attacks.</a><br>"
    ),
    "enot65537": (
        "<a href='/docs/exponent.html'>RSA exponent is not the recommended default value (e ="
        " 65537).</a><br>"
    ),
    "dsa": "<a href='/docs/dsa.html'>DSA keys are not recommended any more.</a>",
}
