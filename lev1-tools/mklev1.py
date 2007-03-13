#!/usr/bin/python

import sys, os

# defaults
VERSION= 1
CHUNKSIZE= 128 * 1024
CHUNKSPERDIR= 512
MAXNUMDIRS= 512

INDEXFILE= "index.lev1"
KEYRING= "keyring"

if len(sys.argv) != 3:
    print "Usage: %s <dest-dir> <size>[kmg]" % sys.argv[0]
    sys.exit(0)

destdir, size = sys.argv[1:]

# convert volume size to bytes
exp = { 'k' : 1024, 'm' : 1024 * 1024, 'g' : 1024 * 1024 * 1024,
	'K' : 1024, 'M' : 1024 * 1024, 'G' : 1024 * 1024 * 1024 }
try:
    if size[-1] in 'kmg':
	size = int(size[:-1]) * exp[size[-1]]
    else: size = int(size)
except ValueError:
    print "Failed to convert \"%s\" to a valid size" % size
    sys.exit(0)

# how many chunks and directories do we need (rounding up)
NUMCHUNKS = (size + CHUNKSIZE - 1) / CHUNKSIZE
NUMDIRS = (NUMCHUNKS + CHUNKSPERDIR - 1) / CHUNKSPERDIR
VOLSIZE = NUMCHUNKS * CHUNKSIZE

if NUMDIRS > MAXNUMDIRS:
    print "Image size too large, format only supports up to %f GB parcels" % \
	((CHUNKSIZE * CHUNKSPERDIR * MAXNUMDIRS) / (1024 * 1024 * 1024))
    sys.exit(0)

if os.path.exists(destdir):
    print "Error: \"%s\" already exists" % destdir
    sys.exit(0)

def processchunk(chunk):
    from zlib import compress
    import Crypto.Hash.SHA as hash
    import Crypto.Cipher.Blowfish as cipher

    # compress the chunk
    compressed = compress(chunk, 9)

    # extract encryption key based on the compressed data
    key1 = hash.new(compressed).digest()
    ekey = key1[:16] # vulpes bug?

    # encrypt chunk using zero iv, blowfish encryption and pkcs block padding
    iv = '\0' * cipher.block_size
    pkcs_val = cipher.block_size - (len(compressed) % cipher.block_size)
    alg = cipher.new(ekey, cipher.MODE_CBC, iv)
    encrypted = alg.encrypt(compressed + chr(pkcs_val) * pkcs_val)

    # lookup key based on the final encrypted data
    key2 = hash.new(encrypted).digest() # lookup key

    return (key1, key2, encrypted)

# create compressed/encrypted zero filled chunk
key1, key2, encrypted = processchunk('\0' * CHUNKSIZE)

# write chunks to disk
os.mkdir(destdir, 0700)

for i in range(NUMCHUNKS):
    dir = os.path.join(destdir, "%04d" % (i / CHUNKSPERDIR))

    if not os.path.exists(dir):
	os.mkdir(dir)

    chunk = os.path.join(dir, "%04d" % (i % CHUNKSPERDIR))
    f = open(chunk, 'w')
    f.write(encrypted)
    f.close()

# create keyring
key1, key2 = map(lambda x:x.encode('hex').upper(), (key1, key2))

keyring = open(os.path.join(destdir, KEYRING), 'a')
for n in range(NUMCHUNKS):
    keyring.write("%s %s\n" % (key2, key1))
keyring.close()

# create index
index = open(os.path.join(destdir, INDEXFILE), 'w')
index.write("""\
VERSION= %(VERSION)s
CHUNKSIZE= %(CHUNKSIZE)s
CHUNKSPERDIR= %(CHUNKSPERDIR)s
VOLSIZE= %(VOLSIZE)s
NUMCHUNKS= %(NUMCHUNKS)s
NUMDIRS= %(NUMDIRS)s
""" % vars())
