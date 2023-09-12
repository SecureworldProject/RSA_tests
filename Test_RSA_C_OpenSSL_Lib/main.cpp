#include <stdio.h>
#include <stdlib.h>
#include <string>

//#define OPENSSL_API_COMPAT 0x10100000L
//#define OPENSSL_API_COMPAT 0x30000000L
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

/*#pragma comment(lib, "libcryptoMD.lib")
#pragma comment(lib, "libcryptoMDd.lib")
#pragma comment(lib, "libcryptoMT.lib")
#pragma comment(lib, "libcryptoMTd.lib")
#pragma comment(lib, "libsslMD.lib")
#pragma comment(lib, "libsslMDd.lib")
#pragma comment(lib, "libsslMT.lib")
#pragma comment(lib, "libsslMTd.lib")*/

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

#include <openssl/err.h>

#define KEY_BYTES_SIZE (512)
#define PADDING_BYTES_SIZE (42)
#define TEST_TEXT_SIZE (KEY_BYTES_SIZE) - (PADDING_BYTES_SIZE)

using namespace std;




// Generates an RSA keypair and saves it into files. Names must not be NULL, empty strings or equal to each other
// Recommended args:
//     public_exponent: RSA_F4 = 65537
//     key_size: 2048
//     private_key_filename: "private_key"
//     public_key_filename: "public_key"
//     rsa_key_to_return: if it is NULL, it is not used. If not, if it filled with a pointer to the RSA keypair.
// Returns 0 if OK. Other value if 
int generate_and_write_key(unsigned long public_exponent, int key_bitsize, const char* private_key_filename, const char* public_key_filename, RSA** rsa_key_to_return) {
	int ret = 0;
	int error = 0;
	RSA* rsa_keypair = NULL;
	BIGNUM* bne = NULL;
	BIO* bio_public = NULL;
	BIO* bio_private = NULL;

	// Check inputs
	if (NULL == private_key_filename || "" == private_key_filename) {
		return 0;	// ERROR
	}
	if (NULL == public_key_filename || "" == public_key_filename) {
		return 0;	// ERROR
	}
	if (private_key_filename == public_key_filename) {
		return 0;	// ERROR
	}

	// Generate RSA key pair
	bne = BN_new();
	ret = BN_set_word(bne, public_exponent);
	if (1 != ret) {
		error = 1;
		goto GEN_KEY_CLEANUP;
	}

#pragma warning(suppress : 4996)
	rsa_keypair = RSA_new();
#pragma warning(suppress : 4996)
	ret = RSA_generate_key_ex(rsa_keypair, key_bitsize, bne, NULL);
	if (1 != ret) {
		error = 2;
		goto GEN_KEY_CLEANUP;
	}

	// Save public key
	bio_public = BIO_new_file(public_key_filename, "w+");
#pragma warning(suppress : 4996)
	ret = PEM_write_bio_RSAPublicKey(bio_public, rsa_keypair);
	if (1 != ret) {
		error = 3;
		goto GEN_KEY_CLEANUP;
	}

	// Save private key
	bio_private = BIO_new_file(private_key_filename, "w+");
#pragma warning(suppress : 4996)
	ret = PEM_write_bio_RSAPrivateKey(bio_private, rsa_keypair, NULL, NULL, 0, NULL, NULL);
	if (1 != ret) {
		error = 4;
		goto GEN_KEY_CLEANUP;
	}

#pragma warning(suppress : 4996)
	printf("RSA_size dentro: %d\n", RSA_size(rsa_keypair));

	// Cleanup
GEN_KEY_CLEANUP:
	BIO_free_all(bio_public);
	BIO_free_all(bio_private);
	BN_free(bne);
	if (error || NULL == rsa_key_to_return) {
#pragma warning(suppress : 4996)
		RSA_free(rsa_keypair);
		return error;
	} else {
		*rsa_key_to_return = rsa_keypair;
	}

	return error;
}

// Reads a public key. The returned pointer must be freed after use with "RSA_free()"
RSA* read_public_key(const char* public_key_filename) {
	int ret = 0;

	RSA* rsa_key = NULL;
	BIO* bio_public = NULL;

	// This would be the non-deprecated method
	//EVP_PKEY* pkey = PEM_read_PublicKey(....);

	// Read public key
	bio_public = BIO_new_file(public_key_filename, "r");
#pragma warning(suppress : 4996)
	PEM_read_bio_RSAPublicKey(bio_public, &rsa_key, 0, NULL);
	if (NULL == rsa_key) {
		return NULL;
	}

	return rsa_key;
}

// Reads a private key. The returned pointer must be freed after use with "RSA_free()"
RSA* read_private_key(const char* private_key_filename) {
	int ret = 0;

	RSA* rsa_key = NULL;
	BIO* bio_private = NULL;


	// This would be the non-deprecated method
	//EVP_PKEY* pkey = PEM_read_PrivateKey(file, NULL, pem_password_callback, NULL);

	// Save private key
	bio_private = BIO_new_file(private_key_filename, "r");
#pragma warning(suppress : 4996)
	PEM_read_bio_RSAPrivateKey(bio_private, &rsa_key, 0, NULL);
	if (NULL == rsa_key) {
		return NULL;
	}

	return rsa_key;
}





int main() {
	char pub_key_filename[] = "keypair_mondragon_pub.pem"; //"public_key_4";
	char priv_key_filename[] = "keypair_mondragon_priv.pem"; //"private_key_4";
	char test_file_name[] = "test_file_mondragon"; //"test_file";

	unsigned char test_text[TEST_TEXT_SIZE] = "Esto es un texto de prueba. En algun lugar de la Mancha de cuyo nombre no quiero acordarme...";
	unsigned char* encrypted_text = NULL;
	unsigned char* decrypted_text = NULL;
	int test_text_size = TEST_TEXT_SIZE;
	int encrypted_text_size = 0;
	int decrypted_text_size = 0;

	FILE* f_test_file = NULL;

	unsigned long err_code = 0;
	size_t result = 0;
	RSA* rsa_keypair = NULL;
	RSA* rsa_pub_key = NULL;



	// ----------------------------------------------------------------------------------------------------
	// ONLY CREATE A CIPHERED TESTING FILE OF 512 BYTES
	// ----------------------------------------------------------------------------------------------------

	rsa_pub_key = read_public_key(pub_key_filename);
	if (NULL == rsa_pub_key) {
		printf("ERROR: could not read pub key (%s)\n", pub_key_filename);
		return 1;
	}
	printf("File with public key read.\n");
#pragma warning(suppress : 4996)
	printf("RSA_size: %d\n", RSA_size(rsa_pub_key));


#pragma warning(suppress : 4996)
	encrypted_text = (unsigned char*)malloc(RSA_size(rsa_pub_key));
	if (NULL == encrypted_text) {
		printf("ERROR allocating memory for encrypted_text buffer\n");
		return 1;
	}
#pragma warning(suppress : 4996)
	encrypted_text_size = RSA_public_encrypt(test_text_size, test_text, encrypted_text, rsa_pub_key, RSA_PKCS1_OAEP_PADDING);
	if (-1 == encrypted_text_size) {
		err_code = ERR_get_error();
		printf("ERROR encrypting --> %s\n", ERR_error_string(err_code, NULL));
		return 1;
	}

	result = fopen_s(&f_test_file, test_file_name, "wb");
	if (0 == result) {
		result = fwrite(encrypted_text, 1, encrypted_text_size, f_test_file);
		if (encrypted_text_size == result) {
			printf("Everything written to %s correctly\n", test_file_name);
		} else {
			printf("ERROR writing to %s\n", test_file_name);
		}
	} else {
		printf("ERROR opening %s to write\n", test_file_name);
	}

	printf("END!");
	return 0;
	// ----------------------------------------------------------------------------------------------------

	rsa_keypair = (RSA*)malloc(1 * sizeof(RSA*));
	if (0 != generate_and_write_key(RSA_F4, KEY_BYTES_SIZE * 8, priv_key_filename, pub_key_filename, &rsa_keypair)) {
		printf("ERROR...\n");
	}

	/*rsa_pub_key = read_public_key(pub_key_filename);
	if (NULL == rsa_pub_key) {
		printf("ERROR: could not read pub key (%s)\n", pub_key_filename);
		return 1;
	}
	printf("File with public key read.\n");
#pragma warning(suppress : 4996)
	printf("RSA_size: %d\n", RSA_size(rsa_pub_key));*/

	//int RSA_public_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA * rsa, int padding);
	printf("rsa_keypair %s NULL\n", (NULL == rsa_keypair) ? "IS" : "is NOT");

#pragma warning(suppress : 4996)
	encrypted_text = (unsigned char*)malloc(RSA_size(rsa_keypair));
#pragma warning(suppress : 4996)
	encrypted_text_size = RSA_public_encrypt(test_text_size, test_text, encrypted_text, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
	//encrypted_text_size = RSA_public_encrypt(test_text_size, test_text, encrypted_text, rsa_pub_key, RSA_NO_PADDING);
	if (-1 == encrypted_text_size) {
		err_code = ERR_get_error();
		printf("ERROR encrypting --> %s\n", ERR_error_string(err_code, NULL));
	}

	/*
	RSA_public_encrypt() encrypts the flen bytes at from (usually a session key) using the public key rsa and stores the ciphertext in to. to must point to RSA_size(rsa) bytes of memory.
	padding denotes one of the following modes:
		RSA_PKCS1_PADDING
			PKCS #1 v1.5 padding. This currently is the most widely used mode. However, it is highly recommended to use RSA_PKCS1_OAEP_PADDING in new applications. SEE WARNING BELOW.
		RSA_PKCS1_OAEP_PADDING
			EME-OAEP as defined in PKCS #1 v2.0 with SHA-1, MGF1 and an empty encoding parameter. This mode is recommended for all new applications.
		RSA_NO_PADDING
			Raw RSA encryption. This mode should only be used to implement cryptographically sound padding modes in the application code. Encrypting user data directly with RSA is insecure.
	*/

#pragma warning(suppress : 4996)
	decrypted_text = (unsigned char*)malloc(RSA_size(rsa_keypair) - PADDING_BYTES_SIZE);
#pragma warning(suppress : 4996)
	decrypted_text_size = RSA_private_decrypt(encrypted_text_size, encrypted_text, decrypted_text, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
	if (-1 == decrypted_text_size) {
		err_code = ERR_get_error();
		printf("ERROR decrypting --> %s\n", ERR_error_string(err_code, NULL));
	}

	printf("test_text (size:%d):\n%s\n\n", test_text_size, test_text);
	printf("encrypted_text (size:%d):\n%.*s\n\n", encrypted_text_size, encrypted_text_size, (char*)encrypted_text);
	printf("decrypted_text (size:%d):\n%.*s\n\n", decrypted_text_size, decrypted_text_size, (char*)decrypted_text);

	result = fopen_s(&f_test_file, test_file_name, "wb");
	if (0 == result) {
		result = fwrite(encrypted_text, 1, encrypted_text_size, f_test_file);
		if (encrypted_text_size == result) {
			printf("Everything written to %s correctly\n", test_file_name);
		} else {
			printf("ERROR writing to %s\n", test_file_name);
		}
	} else {
		printf("ERROR opening %s to write\n", test_file_name);
	}


	printf("DONE!\n");
	return 0;
}
