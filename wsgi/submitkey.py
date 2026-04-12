# SPDX-License-Identifier: MIT

import datetime
import json
import os
import pathlib

from bkweb import htmlbottom, htmltop

htmlcontent = """<h2>Key submitted!</h2>
<p>Thanks for submitting a private key. It will be reviewed and
added to badkeys' blocklist if appropriate.</p>
"""


def submitkey(d):
    jdata = json.dumps(d, indent=4) + "\n"
    outdir = os.path.expanduser("~/badkeyssubmissions")
    fn = datetime.datetime.now(datetime.UTC).isoformat()
    ofp = os.path.join(outdir, fn)
    pathlib.Path(ofp).write_text(jdata)
    return htmltop() + htmlcontent + htmlbottom
