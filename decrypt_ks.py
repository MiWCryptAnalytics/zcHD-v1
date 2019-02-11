import logging, sys, os
import base64
import binascii
import json
import nacl.secret
import nacl.public
import nacl.utils
from PIL import Image
from lib import get_ciphertext_array_alpha
from lib import HDKey
from lib import words_to_seed, mn_seed_from_root_seed, get_account_int_from_str


#logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

def main():
    if len(sys.argv) == 1:
        print(f"Usage: python {sys.argv[0]} FILENAME")
        return -1
    inputfile = sys.argv[1]
    img = Image.open(inputfile)
    ct_ba, ks_ba, md_ba = get_ciphertext_array_alpha(img)
    image_key_bag = json.loads(ks_ba)
    metadata_details = json.loads(md_ba)

    sender_name = metadata_details['name']
    sender_pk = metadata_details['pk']

    ## load other party keys
    my_name = "@bob@zax.cloud"
    phrase = b"cabbage harsh word gossip mercy pudding acoustic trophy toast wine sport ready invest fade truth record history expect assist hammer island inmate index evidence"
    password = b"pizza"

    root_seed = words_to_seed(phrase, password)
    master_node_seed = mn_seed_from_root_seed(root_seed)
    hd_mnode = HDKey(master_node_seed)

    purpose = 67
    coin_type = 1
    account = get_account_int_from_str(my_name)
    generation = 0
    localkeyring = []
    keyring = {}
    id_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(0).get_child(generation)
    localkeyring.append(id_key)
    for color in range(1,8):
        color_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(color).get_child(generation)
        localkeyring.append(color_key)

    # pre shared red private key
    id_pk_cache = {"@miw@zax.cloud" : 'WFZSRRFjSY/vnRJ7JwcdEw4Viu1Eui1+ne24fcBQH3A='}
    shared_gsk_cache = {"abY0KofWl0pDZMHKMRPx0kHJgyp1W0Lj2UYtNXP/Whk=" : 'L4fQhCnhMMWALKjxI0S8FixZ4TFSIqlZmCJ0/JIURp9NbNCfCTwDe5bLEhYV59IooEkAlGIJLMC/0pZSV5PCGLGtZ4+DTzHj'}

    for cache in shared_gsk_cache:
        wrapped_group_key = shared_gsk_cache[cache]
        sender_pk = nacl.public.PublicKey(id_pk_cache[sender_name], encoder=nacl.encoding.Base64Encoder)
        group_key_box = nacl.public.Box(id_key.sk, sender_pk)
        gk = base64.b64encode(group_key_box.decrypt(wrapped_group_key, encoder=nacl.encoding.Base64Encoder))
        keyring[sender_name] = {cache : gk}

    logging.debug(f"Keyring: {keyring}")
    logging.debug(f"Decrypting {inputfile} shared by {sender_name}")

    wrappedkey = None
    unwrapping_key = None
    for k in keyring[sender_name]:
        b64_key = nacl.public.PublicKey(k, encoder=nacl.encoding.Base64Encoder).encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8')
        #print(f"public key found in keybag: {b64_key}")
        if b64_key in image_key_bag:
            wrappedkey = image_key_bag[b64_key]
            #print(f"wrapped key {wrappedkey}")
            group_key = keyring[sender_name][k]
            #print(f"group private key: {group_key}")
            unwrapping_key = nacl.public.PrivateKey(group_key, encoder=nacl.encoding.Base64Encoder)
            break
    if not (wrappedkey):
        raise Exception('Cannot Decrypt Image, No public key matched in image key bag')
    if not (unwrapping_key):
        raise Exception('Cannot Decrypt Image, Could not decrypt unwrapping key')

    logging.debug(f"Decrypting image key from keybag {inputfile}")
    img_sk_unwrap_box = nacl.public.SealedBox(unwrapping_key)
    img_sk = img_sk_unwrap_box.decrypt(wrappedkey, encoder=nacl.encoding.Base64Encoder)
    logging.debug(f"Recovered Image Key: {binascii.hexlify(img_sk)}")
    imagebox = nacl.secret.SecretBox(img_sk)

    # get rid of the encrypted extension
    decrypt_file = 'decrypted.' + inputfile.replace(".zaxcloudenc.png", "")

    mimebox = nacl.secret.SecretBox(img_sk)
    filetype, encrypted_file_ext = mimebox.decrypt(metadata_details['mime'].encode('utf-8'), encoder=nacl.encoding.Base64Encoder).decode('utf-8').strip().split(",")

    print(f"Extracted MIME type: {filetype} {encrypted_file_ext}" )
    file_ext = os.path.splitext(decrypt_file)[1]
    if not (file_ext == encrypted_file_ext):
        decrypt_file = decrypt_file + encrypted_file_ext
    print(f"Decrypting file {inputfile} to {decrypt_file}")
    f = open(decrypt_file, "wb")
    f.write(imagebox.decrypt(bytes(ct_ba)))
    f.close()


if __name__ == '__main__':
    main()
