# zax.cloud hierarchical deterministic keys for nacl curve25519 PublicBox implementation
from datetime import datetime
import mnemonic
import base64
from hashlib import blake2b
from lib import MASTERNODE_KDF_KEY, MASTERNODE_PERSON, ZAXCLOUD_MNEMONIC_SALT
from lib import HDKey
from lib import words_to_seed
from lib import Color
import nacl.encoding


def main():
    m = mnemonic.Mnemonic('english')
    #phrase = m.generate(strength=256)
    # Vector Phrase
    name = "@miw@zax.cloud"
    phrase = b"bunker ketchup tower timber acid wink awesome chicken basket easy arena rough slice uncle topic labor peanut chef nose tuna guess rubber snack choice"
    password = b""

    print("--- Test Vector:")
    print(f"version: {ZAXCLOUD_MNEMONIC_SALT}")
    print(f"phrase: {phrase}")
    print(f"password: {password}")

    root_seed = words_to_seed(phrase, password)
    print(f"root seed: {base64.b64encode(root_seed).decode('utf-8')}")
    blake_hmac = blake2b(key=MASTERNODE_KDF_KEY, digest_size=64, person=MASTERNODE_PERSON)
    blake_hmac.update(root_seed)
    master_node_seed = blake_hmac.digest()
    print(f"master node seed: {base64.b64encode(master_node_seed).decode('utf-8')}")


    # generate HD master node object
    hd_mnode = HDKey(master_node_seed)
    print(hd_mnode)

    # benchmark
    start = datetime.now()
    big_range = 20
    for i1 in range(0, big_range):
        for i2 in range(0, big_range):
            for i3 in range(0, big_range):
                k = hd_mnode.get_child(i1).get_child(i2).get_child(i3)
                # print(k)
                continue

    end = datetime.now()
    number_generated=big_range**3
    print(f"{number_generated} {end-start} {(end-start)/number_generated}/key")

    print(hd_mnode.get_child(4).get_child(17).get_child(27))
    print(hd_mnode.get_child(44).get_child(39).get_child(1043334))
    print(hd_mnode.get_child(44).get_child(39).get_child(1043333))
    print(hd_mnode.get_child(44).get_child(39).get_child(1043332))

    # similar to bip44 layout
    # m / purpose' / coin_type' / account' / change / address_index
    print(hd_mnode.get_child(0).get_child(0).get_child(0).get_child(0).get_child(0))
    # purpose = 67 # v1 purpose
    # coin_type = 1 # v1 purpose
    # account = 4 bytes of blake2s(name)
    # change = color, 0 to 7, clear (my keys), red to violet
    h = blake2b(digest_size=4)
    h.update(name.encode('utf-8'))
    account = int.from_bytes(h.digest(), byteorder='big')
    generation = 0
    id_key = hd_mnode.get_child(67).get_child(1).get_child(account).get_child(0).get_child(generation)
    print(f"{'-'*10} Example User")
    print(f"{name} Zax.Cloud Identity Public Key Gen. {generation} {id_key.pk.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8)')}")
    for color in range(1,7):
        color_key = hd_mnode.get_child(67).get_child(1).get_child(account).get_child(color).get_child(generation)
        print(f"{name} Zax.Cloud { str(Color(color)).replace('Color.', '')} Public Key Gen. {generation} {color_key.pk.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8')}")

    print('-'*10)
    print(hd_mnode.get_child(4).get_child(17).get_child(27))


if __name__ == '__main__':
    main()
