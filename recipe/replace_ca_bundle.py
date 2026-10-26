"""Replace stripe's vendored CA bundle with the one from the ca-certificates package.

The bundle shipped in the stripe sdist includes eMudhra roots whose intermediates were
compromised (https://github.com/stripe/stripe-python/issues/1954). ca-certificates is
kept current by the Mozilla root program, so use its bundle instead.

The vendored file is checked against a recorded sha256 first. If a newer stripe ships a
different file this fails on purpose, so the override is not carried forward unreviewed.
"""
import hashlib
import os
import shutil
import sys

# sha256 of stripe 16.0.0 stripe/data/ca-certificates.crt
EXPECTED_SHA256 = "f1407d974c5ed87d544bd931a278232e13925177e239fca370619aba63c757b4"

vendored = os.path.join(os.environ["SRC_DIR"], "stripe", "data", "ca-certificates.crt")
prefix = os.environ["PREFIX"]
if sys.platform == "win32":
    prefix = os.path.join(prefix, "Library")
replacement = os.path.join(prefix, "ssl", "cacert.pem")

with open(vendored, "rb") as f:
    actual = hashlib.sha256(f.read()).hexdigest()
if actual != EXPECTED_SHA256:
    sys.exit(
        "stripe/data/ca-certificates.crt sha256 is %s, expected %s. The vendored bundle changed: "
        "check whether it still has compromised eMudhra roots, then update or drop "
        "recipe/replace_ca_bundle.py." % (actual, EXPECTED_SHA256)
    )

shutil.copyfile(replacement, vendored)
print("Replaced %s with %s" % (vendored, replacement))
