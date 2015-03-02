#!/usr/bin/env python

from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

message = "I want this stream signed"
digest = SHA256.new()
digest.update(message)


secret_key = False
with open ("/tmp/gpg/private_key.pem", "r") as myfile:
    secret_key = RSA.importKey(myfile.read())

signer = PKCS1_v1_5.new(secret_key)

sig = signer.sign(digest)
sig_encode = b64encode(sig)


verifier = PKCS1_v1_5.new(secret_key.publickey())
verified = verifier.verify(digest, sig)
assert verified

import ipdb; ipdb.set_trace()