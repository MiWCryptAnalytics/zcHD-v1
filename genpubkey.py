from nacl.public import PrivateKey
import nacl.utils

def main():
	skalice = PrivateKey.generate()
	pkalice = skalice.public_key
	ps = skalice.encode(encoder=nacl.encoding.Base64Encoder)
	pp = pkalice.encode(encoder=nacl.encoding.Base64Encoder)
	print(f"secret: {ps}")
	print(f"public: {pp}")


if __name__ == '__main__':
	main()