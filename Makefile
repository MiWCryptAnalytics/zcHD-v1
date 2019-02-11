testrandom:
	dd if=/dev/urandom of=randomfile bs=3M count=1 && python encrypt_ks.py randomfile && python decrypt_ks.py randomfile.zaxcloudenc.png
testjpg:
	convert -size 1024x1024 plasma:fractal random.jpg && python encrypt_ks.py random.jpg && python decrypt_ks.py random.jpg.zaxcloudenc.png
cleanup:
	rm random.jpg randomfile random.zaxcloud.enc.png decrypted.random.jpg decrypted.randomfile