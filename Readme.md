# ZXHD-v1
## Zax.Cloud Hierarchical Deterministic Keys for nacl x25519 
needs:
 * python3
 * Pillow
 * magic
 * nacl
 * argon2
 * numpy

Development repo for zxhd keys

* lib.py has most of the specific codec and helper functions and constants


This is a work in progress. Do not use for anything yet.



## Example run
```code
$ make testjpg
$ make testrandom
$ python encrypt_ks.py filename
$ python decrypt_ks.py filename.zaxcloud.enc
```


Credits and Licenses:
Inconsolata TrueType Font
Copyright (c) Raph Levien 2006
This Font Software is licensed under the SIL Open Font License, Version 1.1.

Orbitron TrueType Font
Copyright (c) 2009, Matt McInerney
This Font Software is licensed under the SIL Open Font License, Version 1.1.

Network and Cryptography Library
public domain - djb

Python Pillow
Copyright © 1997-2011 by Secret Labs AB
Copyright © 1995-2011 by Fredrik Lundh
Copyright © 2010-2019 by Alex Clark and contributors
Open source PIL Software License

PyNaCl
Apache 2.0 License

Argon2 python library
Apache License

Numpy python library
Copyright © 2005-2018, NumPy Developers
NumPy license