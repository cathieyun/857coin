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

def find_collision(b, start1, start2, i, CHAIN_LENGTH):
    # print 'in find collision'
    x = 0
    b["nonces"][1] = start1

    b["nonces"][2] = start2
    d = b["difficulty"]

    while x < CHAIN_LENGTH-i-1:
        hashed_block = hash_block_nonce_i(b,1).encode('hex')
        hash1 = int(hashed_block, 16) %2**d

        # hash1 = hash_nonce(b["nonces"][1], d)

        b["nonces"][1] = hash1
        x+=1

    if b["nonces"][1] != b["nonces"][2]:
        while x < CHAIN_LENGTH:
            hashed_block = hash_block_nonce_i(b,1).encode('hex')
            hash1 = int(hashed_block, 16) %2**d

            # hash1 = hash_nonce(b["nonces"][1], d)

            hashed_block = hash_block_nonce_i(b,2).encode('hex')
            hash2 = int(hashed_block, 16) %2**d

            # hash2 = hash_nonce(b["nonces"][2], d)

            if hash1 == hash2:
                # print 'collision found ' + str([b["nonces"][1] , b["nonces"][2] , hash1])
                return [b["nonces"][1] , b["nonces"][2] , hash1]
            else:
                b["nonces"][1] = hash1
                b["nonces"][2] = hash2
                x+=1
        # print "same start " + str(b["nonces"][1] == b["nonces"][2])
        # print 'same start'
        return [None, None, False]
    return [None, None, False]

def hash_nonce(nonce, d):
    new_hash = H(str(nonce)).digest().encode('hex')
    return int(new_hash,16) % 2**d

def hash_nonce_block(nonce, d, b,i):
    b["nonces"][0] = nonce
    hashed_block = hash_block_nonce_i(b,i).encode('hex')
    current_hash = int(hashed_block, 16) %2**d
    return current_hash

def naiive(nonce_dict, b):
    d = b["difficulty"]
    stored_keys = nonce_dict.keys()
    while True:
        new_nonce = rand_nonce(b["difficulty"])
        b["nonces"][0] = new_nonce
        new_hash = hash_block_nonce_i(b,0).encode('hex') 
        new_hash = int(new_hash, 16) % 2**d
        if new_hash in stored_keys:
            print 'hash in dict'
            if new_nonce not in nonce_dict[new_hash]:
                print 'found nonce'
                b["nonces"] = nonce_dict[new_hash] + [new_nonce]
                return



def solve_block(b):
    """
    Iterate over random nonce triples until a valid proof of work is found
    for the block

    Expects a block dictionary `b` with difficulty, version, parentid,
    timestamp, and root (a hash of the block data).

    """
    print "in solve block"
    CHAIN_LENGTH = 10000
    d = b["difficulty"]
    chainStart = {} # tail --> start
    nonceMap = {}
    tailList = []

    tailToChain = {}
    x = 0
    while True:
        new_start = rand_nonce(b["difficulty"])
        # print '\n  new chain ' + str(new_start)
        current_hash = new_start

        i = 0
        found = False

        while i < CHAIN_LENGTH-1:
            i += 1

            # current_hash = hash_nonce_block(current_hash, d, b,0)
            
            b["nonces"][0] = current_hash
            hashed_block = hash_block_nonce_i(b,0).encode('hex')
            current_hash = int(hashed_block, 16) % 2** d 

            # current_hash = hash_nonce(current_hash, d)

            if current_hash in tailList and found == False:
                found = True
                
                # print "found in tail list"
                # print [current_hash, len(tailList)]

                saved_start = chainStart[current_hash]
                [nonce1, nonce2, image] = find_collision(b, saved_start, new_start,i, CHAIN_LENGTH)

                if image:
                    print x
                    x+=1
                    if image in nonceMap:
                        "in nonce map"
                        existingNonce = nonceMap[image]
                        if nonce1 not in existingNonce and nonce2 not in existingNonce:
                            b["nonces"] = existingNonce + [nonce1]
                            print "found! case 1 "  + str(b["nonces"])
                            return
                        elif nonce1 in existingNonce and nonce2 not in existingNonce:
                            b["nonces"] = existingNonce + [nonce2]
                            print "found! case 2 " + str(b["nonces"])
                            return
                        elif nonce2 in existingNonce and nonce1 not in existingNonce:
                            b["nonces"] = existingNonce + [nonce1]
                            print "found! case 3 " + str(b["nonces"])
                            return
                    else:
                        nonceMap[image] = [nonce1, nonce2]

            if i == CHAIN_LENGTH-1:
                tailList.append(current_hash)
                chainStart[current_hash] = new_start
            if x > 1000:
                naiive(nonceMap, b)
                return
    return 

def check_nonces(b, d):
    print b["nonces"]
    new_hash = []
    for i in range(len(b["nonces"])):
        print b["nonces"][i]
        hashed_block = hash_block_nonce_i(b,i).encode('hex')
        # print 'hashed block ' + str(hashed_block)
        int_hashed_block = int(hashed_block, 16) % 2** d 
        print 'int hashed block ' + str(int_hashed_block)
        new_hash.append(int_hashed_block)
    # new_hash = [int(hash_block_nonce_i(b,i).encode('hex') , 16) %2**d for i in range(len(b["nonces"]))]
    if ((new_hash[0] == new_hash[1]) and (new_hash[1] == new_hash[2])):
        print "check nonces true"
    else:
        print "check nonces false"
        print new_hash

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
    "difficulty": 37,
    "root": hash_to_hex(block_contents),
    "timestamp": long((time.time()+600)*1000*1000*1000),
    "version": 0,
    "nonces": [0, 0, 0]
    }

    solve_block(test_block)
    print test_block["nonces"]
    b["timestamp"] = long((time.time())*1000*1000*1000)
    check_nonces(test_block, 37)

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
    
    # print 'in hash block nonce i '+str(pack('>Q', long(b["nonces"][i])))

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
