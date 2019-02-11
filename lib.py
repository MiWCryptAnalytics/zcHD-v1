import math
from enum import Enum
import logging, sys
import json
from datetime import datetime
from hashlib import blake2b
import argon2
from PIL import Image, ImageDraw, ImageFont
import nacl.secret
import nacl.public
import nacl.encoding
import numpy as np

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
# logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

## Maxsize = 512kiB
MAXPIXELS = 1080 * 1080
W = math.ceil(math.sqrt(MAXPIXELS))
H = math.ceil(math.sqrt(MAXPIXELS))
# this is just a guess at max. its close. image size * 3 (RBG) - nonce - 3* rows for header,ks,md
MAXDATA = W*H*3 - nacl.secret.SecretBox.NONCE_SIZE - W*3*3
CODEC_VERSION="0.9.4"

MASTERNODE_KDF_KEY = b'zax.cloud master node KDF #v1.0 :-)'
MASTERNODE_PERSON = b'zax.cloud[mnode]'
ZAXCLOUD_MNEMONIC_SALT = b'zax.cloud.mnemonic.v1'
CKD_PERSON = b'[child]'
ZAXCLOUD_ROOT_KDF_t = 32
ZAXCLOUD_ROOT_KDF_m = 16
ZAXCLOUD_ROOT_KDF_p = 16

class Color(Enum):
    RED = 1
    ORANGE = 2
    YELLOW = 3
    GREEN = 4
    BLUE = 5
    INDIGO = 6
    VIOLET = 7

class HDKey():
    def __init__(self, seed, child_number=0, depth=0, parent=None):
        self.parent = parent
        self.seed = seed
        self.child_number = child_number
        self.depth = depth
        seed_L = self.seed[:32]
        seed_R = self.seed[32:]
        self.chaincode = seed_R
        self.sk = nacl.public.PrivateKey.from_seed(seed_L)
        self.pk = self.sk.public_key        

    def getPath(self):
        if self.parent == None:
            return "m"
        else:
         return self.parent.getPath()+f"/{self.child_number}"

    def __repr__(self):
        ret_str = "zcHDv1-"
        ret_str += self.getPath()
        ret_str += f" pk:{self.pk.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8')}, sk:{self.sk.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8')}"
        return ret_str

# similar to https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Child_key_derivation_CKD_functions
# but always hardened. there is no public parent to child public derivation (without chaincode, leaking seed thus private key)
    def get_child(self, child):
        person = child.to_bytes(4, 'big')
        blake_hmac = blake2b(key=self.chaincode,
                       digest_size=64,
                       person=CKD_PERSON+person)
        blake_hmac.update(b'\0')
        blake_hmac.update(bytes(self.pk))
        blake_hmac.update(person)
        child_seed = blake_hmac.digest()
        return HDKey(seed=child_seed, child_number=child, depth=self.depth+1, parent=self)


def get_ciphertext_array_alpha(img):
    enc_array = np.array(img, dtype=np.uint8)
    # codec version check
    assert(np.alltrue(enc_array[0][0] == [0,9,4,255]))
    # extract chunk lengths from header
    # chunk starts on a new line (easier to calculate offsets)
    dp_len = int.from_bytes([enc_array[0][1][2], enc_array[0][1][1], enc_array[0][1][0]], 'big')
    ks_len = int.from_bytes([enc_array[0][2][2], enc_array[0][2][1], enc_array[0][2][0]], 'big')
    md_len = int.from_bytes([enc_array[0][3][2], enc_array[0][3][1], enc_array[0][3][0]], 'big')
    logging.debug(f"DPlen: {dp_len} KSlen: {ks_len} SDlen: {md_len}")
    dp = 0
    nct = bytearray()
    broken = False
    logging.debug(f"Looking for data at {1} {0}")
    for i in range(1, H+1): # +1 for header row
        if broken:
            break
        for j in range(0, W):
            pixel = enc_array[i][j]
            if dp>=dp_len:
                broken = True
                break
            nct.append(pixel[0])
            dp+=1
            if dp>=dp_len:
                broken = True
                break
            nct.append(pixel[1])
            dp+=1
            if dp>=dp_len:
                broken = True
                break
            nct.append(pixel[2])
            dp+=1
    
    # generate encoded key list
    ks_ba = bytearray()
    ks_ioffset = i
    ks_joffset = 0
    logging.debug(f"Looking for key bag at {ks_ioffset} {ks_joffset}")
    ks_bap = 0
    broken = False
    for i in range(ks_ioffset, H+1):
        if broken:
            break
        for j in range(0, W):
            pixel = enc_array[i][j]
            if ks_bap>=ks_len:
                broken = True
                break
            ks_ba.append(pixel[0])
            ks_bap+=1
            if ks_bap>=ks_len:
                broken = True
                break
            ks_ba.append(pixel[1])
            ks_bap+=1
            if ks_bap>=ks_len:
                broken = True
                break
            ks_ba.append(pixel[2])
            ks_bap+=1
    

    # extract signing details
    md_ba = bytearray()
    md_ioffset = i
    md_joffset = 0
    logging.debug(f"Looking for signing detail at {md_ioffset} {md_joffset}")
    md_bap = 0
    broken = False
    for i in range(md_ioffset, H+1):
        if broken:
            break
        for j in range(0, W):
            pixel = enc_array[i][j]
            if md_bap>=md_len:
                broken = True
                break
            md_ba.append(pixel[0])
            md_bap+=1
            if md_bap>=md_len:
                broken = True
                break
            md_ba.append(pixel[1])
            md_bap+=1
            if md_bap>=md_len:
                broken = True
                break
            md_ba.append(pixel[2])
            md_bap+=1


    return (nct, ks_ba, md_ba)



def ciphertext_to_np(ciphertext, keys, metadata_details):
    """Converts byte's ciphertext dictionary keys and signingdetails"""
    # encode ciphertext to RGB tuples in a zero'd np array
    
    # sanity check
    max_mime_encoded = 176
    if not (len(metadata_details['mime']) == max_mime_encoded):
        print(f"Mime data bad, not {max_mime_encoded}")
        return None

    ba = bytearray(ciphertext)
    data_len = 0
    data = np.zeros((H, W, 3), dtype=np.uint8)
    broken = False
    for i in range(0, H):
        if broken:
            break
        for j in range(0, W):

            try:
                r = 0
                g = 0
                b = 0
                r = ba[data_len]
                data_len+=1
                g = ba[data_len]
                data_len+=1
                b = ba[data_len]
                data_len+=1
                data[i][j] = [r, g, b]
            except IndexError:
                logging.debug(f"last data byte is at: {i},{j}")
                data[i][j] = [r, g, b]
                broken = True
                break


    # generate encoded key list
    ks_str = json.dumps(keys)
    ks_ba = bytearray(ks_str.encode('utf-8'))
    ks_ioffset = i # outer i loop runs before breaking
    ks_joffset = 0 # start of new line

    logging.debug(f"Inserting keys at {ks_ioffset} {ks_joffset}")
    ks_len = 0
    broken = False
    for i in range(ks_ioffset, H):
        if broken:
            break
        for j in range(ks_joffset, W):
            try:
                r = 0
                g = 0
                b = 0
                r = ks_ba[ks_len]
                ks_len+=1
                g = ks_ba[ks_len]
                ks_len+=1
                b = ks_ba[ks_len]
                ks_len+=1
                data[i][j] = [r, g, b]
            except IndexError:
                logging.debug(f"last ks byte is at: {i},{j}")
                data[i][j] = [r, g, b]
                broken = True
                break

    # generate meta data details
    sd_str = json.dumps(metadata_details)
    md_ba = bytearray(sd_str.encode('utf-8'))

    md_ioffset = i # outer i loop runs before breaking
    md_joffset = 0 # start of new line
    logging.debug(f"Inserting sd at {md_ioffset} {md_joffset}")
    md_len = 0
    broken = False
    for i in range(md_ioffset, H):
        if broken:
            break
        for j in range(md_joffset, W):
            try:
                r = 0
                g = 0
                b = 0
                r = md_ba[md_len]
                md_len+=1
                g = md_ba[md_len]
                md_len+=1
                b = md_ba[md_len]
                md_len+=1
                data[i][j] = [r, g, b]
            except IndexError:
                logging.debug(f"last sd byte is at: {i},{j}")
                data[i][j] = [r, g, b]
                broken = True
                break
    
    # signature over data + metadata


    # generate header
    header = np.zeros((1, W, 3), dtype=np.uint8)
    # 1, 0, 9 = version 0.9
    header[0][0] = [0, 9, 4]
    # number of bytes in ciphertext
    data_len_bytes = data_len.to_bytes(3, 'big')
    header[0][1] = [data_len_bytes[2], data_len_bytes[1], data_len_bytes[0]]
    # number of bytes in keys
    ks_len_bytes = ks_len.to_bytes(3, 'big')
    header[0][2] = [ks_len_bytes[2], ks_len_bytes[1], ks_len_bytes[0]]
    # number of bytes in signingdetails
    md_len_bytes = md_len.to_bytes(3, 'big')
    header[0][3] = [md_len_bytes[2], md_len_bytes[1], md_len_bytes[0]]
    formatted_array = np.vstack([header, data])
    return formatted_array


# v1 style mask. Renders quite nicely in mastodon
def make_mask(type, sender_detail):
    mask = Image.new('L', (W, H+1), color=255)
    d = ImageDraw.Draw(mask)
    font1 = ImageFont.truetype(font="Orbitron-Regular.ttf", size=100, index=0, encoding='utf-8')
    group_font = ImageFont.truetype(font="Inconsolata-Regular.ttf", size=38, index=0, encoding='utf-8')
    version_font = ImageFont.truetype(font="Inconsolata-Regular.ttf", size=22, index=0, encoding='utf-8')
    x = 30
    y = 250
    d.text((x,y), "Zax.Cloud", color=255, font=font1)
    d.text((x,y+100), "Encrypted", color=255, font=font1)
    d.text((x,y+200), "Group:", color=255, font=group_font)
    d.text((x,y+250), f"{sender_detail['name']}:{type}", color=255, font=group_font)
    
    gk = f"({sender_detail['name']}:{sender_detail['pk']})"
    gk1, gk2 = gk[:len(gk)//2], gk[len(gk)//2:]
    d.text((x,y+300), gk1, color=255, font=group_font)
    d.text((x,y+350), gk2, color=255, font=group_font)
    d.text((x,y+450), f"{datetime.now()}", color=255, font=group_font)
    d.text((W-90,H-50), CODEC_VERSION, color=255, font=version_font)
    return mask

# reimplement the bip39 kdf to use different construction
def words_to_seed(m, password=''):
    return argon2.argon2_hash(password=m, salt=ZAXCLOUD_MNEMONIC_SALT+password, t=ZAXCLOUD_ROOT_KDF_t, m=ZAXCLOUD_ROOT_KDF_m, p=ZAXCLOUD_ROOT_KDF_p, buflen=64, argon_type=argon2.Argon2Type.Argon2_i)

def mn_seed_from_root_seed(root_seed):
    blake_hmac = blake2b(key=MASTERNODE_KDF_KEY, digest_size=64, person=MASTERNODE_PERSON)
    blake_hmac.update(root_seed)
    return blake_hmac.digest()

def get_account_int_from_str(input_str):
    h = blake2b(digest_size=4)
    h.update(input_str.encode('utf-8'))
    account = int.from_bytes(h.digest(), byteorder='big')
    return account