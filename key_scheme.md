 # Key Scheme
 
 ## Intro
 
 Based on ideas from https://medium.com/bitcraft/hd-wallets-explained-from-high-level-to-nuts-and-bolts-9a41545f5b0
 we should not use bip32 directly to derive as we do not want public parent->public child disclosure
 (all keys should be in hardened form)
 This cryptosystem requires potentially malicious learn children private keys, 
 and these users should not be able to recover other keys.
 We use the Argon KDF as it would not suffer from the same hmac attack against PBKDF2

 bip39 style mnemonic (from trezor) generates a standard 24 word phrase to supply 256 bits of entropy named /phrase/
 there is also an optional /password/ added as a salt in the words->seed transform

 we convert this /phrase/ into a 512-bit /root_seed/ using argon2(phrase, 'zax.cloud.mnemonic'+passphrase, t=32, m=16, p=16, size=64)
 this seed is then key-hashed again blake2b(key='zax.cloud master node KDF v1.0 :-)', person=)
 we then can derive an infinite number of keys similar to bip39, but using blake2b keyed hashing with personalization
 we start by deriving a /master node seed/ with blake2b(key='zax.cloud master node KDF v1.0 :-)', person='zax.cloud[mnode]')

 we then use nacl_cryptobox_seed to create a x25519 public/private keypair from master node seed[:32], /seed_L/
 we store seed[32:] as seed_R, the chaincode


 ## Security

 Unlike BIP32, we cannot derive child public keys from a parent public key. 
 The extended public key, (chaincode + public key) is sufficent to generate all child private keys,
 as this is knowledge of the nacl.public.PrivateKey.to_seed() seed preimage.
 all chaincodes should be considered sensitive, and thus extended public key sensitive
 The cryptosystem relies on disclosure of individual node private keys in order to decrypt image keys
 But we must be able to discard a public key and use the next generation key, and redistribute encrypted group key blobs

 we use system CSPRNG to generate 24 words from the bip39 wordlist in english (can be regionalized but key derivation will change)
 giving us 256 bits of entropy
 this 256 bits is argoned using a fixed version salt and stretched to 512 bits, optionally protectd with a short password
 it is then run through blake with a fixed version key and known person
 left most 256 bits of is given as a seed to nacl.public.PrivateKey.from_seed

 ## Security Components
 * Argon(t = 32, m = 16, p = 16)
  * stretches (256 bits of entropy from words) into 512 bit master node nacl cryptobox seed and chaincode
 * Blake2b hmac 512 key=chaincode, data=public_key - into next child chaincode and nacl cryptobox seed
 * nacl seed -> secret key is one way process; cannot derive seed from sk

 *know: phrase password
  * derive: root_seed master_node_seed
 * know: child public key
  * cannot derive next child as do not know chaincode
 * know: child private key
  * can derive child public key
  * can't derive l_seed? (security: nacl seed derivation)
  * can't derive seed (security: dont know l_seed)
  * cannot derive next child as do not know chaincode
 * know: child seed
  * can derive all chaincode, child private key, child public key for all children
