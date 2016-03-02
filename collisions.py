import hashlib

# Hash(B, i) = SHA256(HexDecode(B.parentid) + HexDecode(B.root) + Bytes(B.difficulty) + Bytes(B.timestamp) + Bytes(B.nonces[i]) + B.version)

print hashlib.sha256("Nobody inspects the spammish repetition").hexdigest()

def Hash(B, i):
  return SHA256(HexDecode(B.parentid) + HexDecode(B.root) + Bytes(B.difficulty) + Bytes(B.timestamp) + Bytes(B.nonces[i]) + B.version)

def SHA256(s):
  return hashlib.sha256(s).hexdigest()

def HexDecode(h):
  return h.decode("hex")