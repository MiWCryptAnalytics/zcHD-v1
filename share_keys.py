import nacl.secret
import nacl.public
import nacl.utils

from lib import HDKey
from lib import Color
from lib import words_to_seed, mn_seed_from_root_seed, get_account_int_from_str
import base64

def main():
    # you know your phrase and password, which means we can derive all public and private keys arbitrarily using HDKey
    name = "@miw@zax.cloud"
    phrase = b"cute ill legal submit unveil rookie hawk shine offer dignity conduct helmet mass winter other toy occur angle shock quantum lyrics card card tortoise"
    password = b"swordfish"

    # normally you would look up the public key from the server
    other_name = "@bob@zax.cloud"
    other_pk = b"j34PdKu8X2vfQ7pH/62uioY6E+IQzGAjmHT4+kXkt24="
    # convert to internal public key
    other_publickey = nacl.public.PublicKey(other_pk, encoder=nacl.encoding.Base64Encoder)

    root_seed = words_to_seed(phrase, password)
    master_node_seed = mn_seed_from_root_seed(root_seed)
    hd_mnode = HDKey(master_node_seed)

    purpose = 67
    coin_type = 1
    account = get_account_int_from_str(name)
    generation = 0
    localkeyring = []
    id_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(0).get_child(generation)
    print(f"{name} {id_key.pk.encode(encoder=nacl.encoding.Base64Encoder)}")
    localkeyring.append(id_key)
    for color in range(1,8):
        color_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(color).get_child(generation)
        print(f"{color_key.pk.encode(encoder=nacl.encoding.Base64Encoder)} {Color(color)}")
        localkeyring.append(color_key)


    kx_cryptobox = nacl.public.Box(id_key.sk, other_publickey)
    local_pk_bytes = localkeyring[1].pk.encode(encoder=nacl.encoding.RawEncoder)
    local_sk_bytes = localkeyring[1].sk.encode(encoder=nacl.encoding.RawEncoder)
    wrapped_group_key = kx_cryptobox.encrypt(local_sk_bytes, encoder=nacl.encoding.Base64Encoder)
    print(f"{name} {base64.b64encode(local_pk_bytes)} has encryped sk {wrapped_group_key} for {other_name} {other_pk}")


if __name__ == '__main__':
    main()