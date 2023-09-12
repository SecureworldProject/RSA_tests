# RSA python test
import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding



'''
Encrypts the test_text
Decrypts the intermediate result
Checks if the result is equal to the original text
'''
def test(private_key, public_key, test_text=b"Esto es un texto de prueba"):

	encrypted_text = public_key.encrypt(
		test_text,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	decrypted_text = private_key.decrypt(
		encrypted_text,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	print(f"test_text ({len(test_text)}):\n{test_text}\n")
	print(f"encrypted_text ({len(encrypted_text)}):\n{encrypted_text}\n")
	print(f"decrypted_text ({len(decrypted_text)}):\n{decrypted_text}\n")
	print("The result of decrypting the result of the encryption of the original text is equal to the original text:", decrypted_text == test_text)




def generate_keys(public_exponent=65537, key_size=2048):
	private_key = rsa.generate_private_key(public_exponent, key_size)
	public_key = private_key.public_key()
	return (private_key, public_key)



def save_keys_on_files(private_key, public_key, private_key_filename="private_key", public_key_filename="public_key"):
	# Serialize private key without encryption with a format like: '-----BEGIN RSA PRIVATE KEY-----' ...
	pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
	with open(private_key_filename, "wb") as file:
		file.write(pem)


	# Serialize the public key with a format like: '-----BEGIN PUBLIC KEY-----' ...
	public_key = private_key.public_key()
	pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	with open(public_key_filename, "wb") as file:
		file.write(pem)


def read_keys_from_files(private_key_filename="", public_key_filename=""):
	private_key = None
	public_key = None

	if private_key_filename:
		try:
			with open(private_key_filename, "rb") as file:
				private_key = serialization.load_pem_private_key(
					file.read(),
					password=None,
				)
		except Exception as e:
			print(f"Error: could not load private key (file: '{private_key_filename}')")
	else:
		print("Warning: private key file not specified")

	if public_key_filename:
		try:
			with open(public_key_filename, "rb") as file:
				public_key = serialization.load_pem_public_key(
					file.read(),
				)
		except Exception as e:
			print(f"Error: could not load public key (file: '{public_key_filename}')")
	else:
		print("Warning: public key file not specified")


	return (private_key, public_key)


### TESTS ###

def test_1_standalone():
	# Create new keys
	(private_key, public_key) = generate_keys()

	# Cipher, decipher and test
	test(private_key, public_key)



def test_2_write_read_keys_files():
	# Create new keys
	(private_key, public_key) = generate_keys()

	# Save keys in file
	save_keys_on_files(private_key, public_key, private_key_filename="private_key_2", public_key_filename="public_key_2")

	# Force clear keys
	del private_key
	del public_key

	# Read keys from files
	(private_key, public_key) = read_keys_from_files(private_key_filename="private_key_2", public_key_filename="public_key_2")

	# Cipher, decipher and test
	test(private_key, public_key)



def test_3_read_keys_files():
	# Read keys from files
	(private_key, public_key) = read_keys_from_files(private_key_filename="private_key_3", public_key_filename="public_key_3")

	# Cipher, decipher and test
	test(private_key, public_key)



def test_4_read_keys_files_and_decrypt_encrypted_file():
	original_encrypted_text_file = "test_file"
	original_encrypted_text = None

	# Read keys from files
	(private_key, public_key) = read_keys_from_files(private_key_filename="private_key_4", public_key_filename="public_key_4")

	# Read original_encrypted_text file
	with open(original_encrypted_text_file, "rb") as file:
		original_encrypted_text = file.read()

	print(f"original_encrypted_text (size={len(original_encrypted_text)}): {original_encrypted_text}")


	# Decrypt text
	new_plaintext = private_key.decrypt(
		original_encrypted_text,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	print(f"original_encrypted_text ({len(original_encrypted_text)}):\n{original_encrypted_text}\n")
	print(f"new_plaintext ({len(new_plaintext)}):\n{new_plaintext}\n")


def test_3b():
	# Read keys from files
	(private_key, public_key) = read_keys_from_files(private_key_filename="keypair_mondragon_priv.pem", public_key_filename="keypair_mondragon_pub.pem")

	# Cipher, decipher and test
	test(private_key, public_key)


def test_4b():
	original_encrypted_text_file = "test_file_mondragon"
	original_encrypted_text = None

	# Read keys from files
	(private_key, public_key) = read_keys_from_files(private_key_filename="keypair_mondragon_priv.pem", public_key_filename="")

	# Read original_encrypted_text file
	with open(original_encrypted_text_file, "rb") as file:
		original_encrypted_text = file.read()

	print(f"original_encrypted_text (size={len(original_encrypted_text)}): {original_encrypted_text}")

	# Decrypt text
	new_plaintext = private_key.decrypt(
		original_encrypted_text,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	print(f"original_encrypted_text ({len(original_encrypted_text)}):\n{original_encrypted_text}\n")
	print(f"new_plaintext ({len(new_plaintext)}):\n{new_plaintext}\n")



### MAIN ###

if __name__ == '__main__':

	#tests_list = [test_1_standalone, test_2_write_read_keys_files, test_3_read_keys_files, test_4_read_keys_files_and_decrypt_encrypted_file]
	#tests_list = [test_3_read_keys_files, test_4_read_keys_files_and_decrypt_encrypted_file]
	tests_list = [test_3b, test_4b]

	for i in range(len(tests_list)):
		print("\n________________________________________________________________________________\n")
		print("FUNCTION: ", tests_list[i].__name__)
		try:
			tests_list[i]()
		except Exception as e:
			print(e)
		print("________________________________________________________________________________\n")
