import logging, sys, os
import magic
import nacl.secret
import nacl.public
import nacl.utils
from PIL import Image

from lib import ciphertext_to_np, MAXDATA, make_mask
from lib import HDKey
from lib import Color
from lib import words_to_seed, mn_seed_from_root_seed, get_account_int_from_str

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

def main():
    if len(sys.argv)==1:
        print(f"Usage: python {sys.argv[0]} FILENAME")
        sys.exit(-1)

    inputfile = sys.argv[1]
    statinfo = os.stat(inputfile)
    if (statinfo.st_size >= MAXDATA):
        print(f"File {inputfile} is too big, {statinfo.st_size} < {MAXDATA}")
        sys.exit(-2)

    # replace the name, phrase and password with your own
    name = "@miw@zax.cloud"
    phrase = b"cute ill legal submit unveil rookie hawk shine offer dignity conduct helmet mass winter other toy occur angle shock quantum lyrics card card tortoise"
    password = b"swordfish"

    imgkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(imgkey)
    root_seed = words_to_seed(phrase, password)
    master_node_seed = mn_seed_from_root_seed(root_seed)
    hd_mnode = HDKey(master_node_seed)

    # purpose = 67 # v1 purpose
    # coin_type = 1 # v1 purpose
    # account = 4 bytes of blake2s(name)
    # color, 0 to 7, 0=clear=my keys, 1=red to 7=violet

    purpose = 67
    coin_type = 1
    account = get_account_int_from_str(name)
    generation = 0
    localkeyring = []
    id_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(0).get_child(generation)
    #print(f"{name} {id_key.pk.encode(encoder=nacl.encoding.Base64Encoder)}")
    localkeyring.append(id_key)
    for color in range(1,8):
        color_key = hd_mnode.get_child(purpose).get_child(coin_type).get_child(account).get_child(color).get_child(generation)
        #print(f"{color_key.pk.encode(encoder=nacl.encoding.Base64Encoder)} {Color(color)}")
        localkeyring.append(color_key)

    mime = magic.Magic(mime=True)
    filetype = mime.from_file(inputfile)
    print(f"Encrypting file {inputfile} of type {filetype}")
    f = open(inputfile, "rb")
    try:
        cleartext = f.read()
        ciphertext = box.encrypt(cleartext)
    finally:
        f.close()

    # decrypt_ks currently only contains a preshared red key. includ this in the recipents to decrypt
    #recipents = [Color.RED, Color.ORANGE, Color.YELLOW, Color.GREEN, Color.BLUE, Color.INDIGO, Color.VIOLET]
    recipents = [Color.RED, Color.ORANGE, Color.YELLOW, Color.GREEN]
    generation = 0
    print(f"Wrapping key for recipents { recipents }")


    keys = {}
    for r in recipents:
        r_key = localkeyring[r.value].pk
        r_box = nacl.public.SealedBox(r_key)
        r_key_str = r_key.encode(encoder=nacl.encoding.Base64Encoder)
        keys[r_key_str.decode('utf-8')] = r_box.encrypt(imgkey, encoder=nacl.encoding.Base64Encoder).decode('utf-8')


    # $ grep -v "#" /etc/mime.types | cut -f1 | wc -L
    # 84
    max_mimelength = 90 # 90 is most that mime types will be. we need a few chars for the ext too.

    mimebox = nacl.secret.SecretBox(imgkey)
    file_ext = os.path.splitext(inputfile)[1]
    padded_filetype = f"{filetype},{file_ext}".ljust(max_mimelength).encode('utf-8')
    encrypted_mime = mimebox.encrypt(padded_filetype, encoder=nacl.encoding.Base64Encoder)

    meta_data = { "pk" : id_key.pk.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8'), "name" : name , "mime": encrypted_mime.decode('utf-8') }
    img = Image.fromarray(ciphertext_to_np(ciphertext, keys, meta_data), 'RGB')

    group_mask_string = ""
    if len(recipents) == 7:
        group_mask_string = "RAINBOW"
    else:
        for r in recipents:
            group_mask_string += f"{r.name}/"

    mask = make_mask(group_mask_string, meta_data)
    img.putalpha(mask)
    print(f"saving {inputfile +'.zaxcloudenc.png'}")
    img.save(inputfile +'.zaxcloudenc.png', compress_level=9)

if __name__ == '__main__':
    main()
