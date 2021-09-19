# /usr/bin/env python3

# CS 642 University of Wisconsin
#
# usage: python3 attack.py ciphertext
# Outputs a modified ciphertext and tag

import sys
import hashlib

# Grab ciphertext from first argument
ciphertextWithTag = bytes.fromhex(sys.argv[1])

if len(ciphertextWithTag) < 16+16+32:
  print("Ciphertext is too short!")
  sys.exit(0)

iv = ciphertextWithTag[:16]
ciphertext = ciphertextWithTag[16:len(ciphertextWithTag)-32]
tag = ciphertextWithTag[len(ciphertextWithTag)-32:]

# TODO: Modify the input so the transfer amount is more lucrative to the recipient
ogmessage = \
"""AMOUNT: $  37.98
Originating Acct Holder: Alexa
Orgininating Acct #98166-20633

I authorized the above amount to be transferred to the account #51779-31226 
held by a Wisc student at the National Bank of the Cayman Islands.
""".encode()

badmessage = \
"""AMOUNT: $9999.99
Originating Acct Holder: Alexa
Orgininating Acct #98166-20633

I authorized the above amount to be transferred to the account #51779-31226 
held by a Wisc student at the National Bank of the Cayman Islands.
""".encode()

badiv = bytearray()
for i in range(16):
  badiv.append(ogmessage[i] ^ iv[i] ^ badmessage[i])
tag = hashlib.sha256(badmessage).hexdigest()
# TODO: Print the new encrypted message
# you can change the print content if necessary
print(badiv.hex() + ciphertext.hex() + tag)
