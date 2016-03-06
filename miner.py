# Original file miner.py from http://courses.csail.mit.edu/6.857/2016/files/miner.py
# The only things that were added are the proof of work (check that n1==n2==n3 in mod 2**d)
# in solve_block(b) and the block_contents (our team names)

import urllib2
import json
#   exclusively use SHA256 as our hash function
from hashlib import sha256 as H
import time
from struct import pack, unpack
import random
import requests

NODE_URL = "http://6857coin.csail.mit.edu:8080"

def solve_block(b):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    d = b["difficulty"]
    nonce_dict = {} # find image --> [nonce]
    all_image = []
    while True:
        new_nonce = rand_nonce(b["difficulty"])
        b["nonces"][0] = new_nonce
        new_hash = hash_block_nonce_i(b,0).encode('hex') 
        new_hash = int(new_hash, 16) % 2**d
        if new_hash in nonce_dict:
            print 'in hash dict, lenth :  ' + str(len(nonce_dict[new_hash]))
            nonce_dict[new_hash].append(new_nonce)
        else:
            # all_image.append(new_hash)
            # print 'new hash'
            nonce_dict[new_hash] = [new_nonce]
        if len(nonce_dict[new_hash]) == 3:
            print 'nonces found!'
            b["nonces"] = nonce_dict[new_hash]
            return 


def main():
    """
    Repeatedly request next block parameters from the server, then solve a block
    containing our team name.

    We will construct a block dictionary and pass this around to solving and
    submission functions.
    """
    block_contents = "cath_yun,cmchin,sa25943" # team names

    test_block = {
    "parentid": "169740d5c4711f3cbbde6b9bfbbe8b3d236879d849d1c137660fce9e7884cae7",
    "difficulty": 38,
    "root": hash_to_hex(block_contents),
    "timestamp": long((time.time()+600)*1000*1000*1000),
    "version": 0,
    "nonces": [0, 0, 0]
    }
    solve_block(test_block)
    
    add_block(test_block, block_contents)

def get_next():
    """
       Parse JSON of the next block info
           difficulty      uint64
           parentid        HexString
           version         single byte
    """
    return json.loads(urllib2.urlopen(NODE_URL + "/next").read())

def add_block(h, contents):
    """
       Send JSON of solved block to server.
       Note that the header and block contents are separated.
            header:
                difficulty      uint64
                parentid        HexString
                root            HexString
                timestampe      uint64
                version         single byte
            block:          string
    """
    add_block_request = {"header": h, "block": contents}
    print "Sending block to server..."
    print json.dumps(add_block_request)
    r = requests.post(NODE_URL + "/add", data=json.dumps(add_block_request))
    print r

def hash_block_to_hex(b):
    """
    Computes the hex-encoded hash of a block header. First builds an array of
    bytes with the correct endianness and length for each arguments. Then hashes
    the concatenation of these bytes and encodes to hexidecimal.

    Not used for mining since it includes all 3 nonces, but serves as the unique
    identifier for a block when querying the explorer.
    """
    packed_data = []
    packed_data.extend(b["parentid"].decode('hex'))
    packed_data.extend(b["root"].decode('hex'))
    packed_data.extend(pack('>Q', long(b["difficulty"])))
    packed_data.extend(pack('>Q', long(b["timestamp"])))
    #   Bigendian 64bit unsigned
    for n in b["nonces"]:
        #   Bigendian 64bit unsigned
        packed_data.extend(pack('>Q', long(n)))
    packed_data.append(chr(b["version"]))
    if len(packed_data) != 105:
	print "invalid length of packed data"
    h = H()
    h.update(''.join(packed_data))
    b["hash"] = h.digest().encode('hex')
    return b["hash"]

def hash_block_nonce_i(b, i):
    """
    Computes the hex-encoded hash of a block header, using only nonce i. First
    builds an array of bytes with the correct endianness and length for each
    arguments. Then hashes the concatenation of these bytes and encodes to
    hexidecimal.
    """

    packed_data = []
    packed_data.extend(b["parentid"].decode('hex'))
    packed_data.extend(b["root"].decode('hex'))
    packed_data.extend(pack('>Q', long(b["difficulty"])))
    packed_data.extend(pack('>Q', long(b["timestamp"])))
    #   Bigendian 64bit unsigned
    packed_data.extend(pack('>Q', long(b["nonces"][i])))
    packed_data.append(chr(b["version"]))
    if len(packed_data) != 89:
	print "invalid length of packed data"
    h = H()
    h.update(''.join(packed_data))
    return h.digest()

def hash_to_hex(data):
    """Returns the hex-encoded hash of a byte string."""
    h = H()
    h.update(data)
    return h.digest().encode('hex')

def make_block(next_info, contents):
    """
    Constructs a block from /next header information `next_info` and sepcified
    contents.
    """
    block = {
        "version": next_info["version"],
        #   for now, root is hash of block contents (team name)
        "root": hash_to_hex(contents),
        "parentid": next_info["parentid"],
        #   nanoseconds since unix epoch
        "timestamp": long(time.time()*1000*1000*1000),
        "difficulty": next_info["difficulty"]
    }
    return block

def rand_nonce(diff):
    """
    Returns a random int in [0, 2**diff)
    """
    return random.randint(0,2**diff-1)
if __name__ == "__main__":
    main()
