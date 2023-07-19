#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>

int main(int argc, char** argv) {
	/*
	struct public_key_class {
		long long modulus;
		long long exponent;
	};

	struct private_key_class {
		long long modulus;
		long long exponent;
	};
	
	// This function generates public and private keys, then stores them in the structures you provide pointers to. The 3rd argument should be the text PRIME_SOURCE_FILE to have it use the location specified above in this header.
	void rsa_gen_keys(struct public_key_class* pub, struct private_key_class* priv, const char* PRIME_SOURCE_FILE);

	// This function will encrypt the data pointed to by message. It returns a pointer to a heap array containing the encrypted data, or NULL upon failure. This pointer should be freed when you are finished. The encrypted data will be 8 times as large as the original data.
	long long* rsa_encrypt(const char* message, const unsigned long message_size, const struct public_key_class* pub);

	// This function will decrypt the data pointed to by message. It returns a pointer to a heap array containing the decrypted data, or NULL upon failure. This pointer should be freed when you are finished. The variable message_size is the size in bytes of the encrypted message. The decrypted data will be 1/8th the size of the encrypted data.
	char* rsa_decrypt(const long long* message, const unsigned long message_size, const struct private_key_class* pub);
	*/

	printf("mymain\n");

	struct public_key_class pub_key = { 0 };
	struct private_key_class priv_key = { 0 };


	const char* test_text = "Esto es un texto de prueba";
	unsigned long test_text_size = strlen(test_text);
	long long* encrypted_text = NULL;
	unsigned long encrypted_text_size = 8 * test_text_size;
	long long* decrypted_text = NULL;
	unsigned long decrypted_text_size = test_text_size;

	rsa_gen_keys(&pub_key, &priv_key, PRIME_SOURCE_FILE);
	encrypted_text = rsa_encrypt(test_text, test_text_size, &pub_key);
	decrypted_text = rsa_decrypt(encrypted_text, encrypted_text_size, &priv_key);

	printf("test_text (size:%d):\n%s\n\n", test_text_size, test_text);
	printf("encrypted_text (size:%d):\n%.*s\n\n", encrypted_text_size, encrypted_text_size, (char*)encrypted_text);
	printf("decrypted_text (size:%d):\n%.*s\n\n", decrypted_text_size, decrypted_text_size, (char*)decrypted_text);

	free(encrypted_text);
	free(decrypted_text);

	return 0;
}



/*

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct public_key_class {
	long long modulus;
	long long exponent;
};

struct private_key_class {
	long long modulus;
	long long exponent;
};

void write_base64(FILE* file, const unsigned char* data, size_t length) {
	static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i;

	for (i = 0; i < length; i += 3) {
		unsigned char triplet[3];
		unsigned char encoded[4];
		int j;

		triplet[0] = data[i];
		triplet[1] = (i + 1 < length) ? data[i + 1] : 0;
		triplet[2] = (i + 2 < length) ? data[i + 2] : 0;

		encoded[0] = base64_table[triplet[0] >> 2];
		encoded[1] = base64_table[((triplet[0] & 0x03) << 4) | (triplet[1] >> 4)];
		encoded[2] = base64_table[((triplet[1] & 0x0F) << 2) | (triplet[2] >> 6)];
		encoded[3] = base64_table[triplet[2] & 0x3F];

		if (i + 1 >= length) {
			encoded[2] = '=';
		}
		if (i + 2 >= length) {
			encoded[3] = '=';
		}

		fwrite(encoded, sizeof(char), 4, file);
	}
}

void generate_pem_file(const char* filename, const struct public_key_class* public_key, const struct private_key_class* private_key) {
	FILE* file = fopen(filename, "w");
	if (file == NULL) {
		printf("Error al abrir el archivo\n");
		return;
	}

	// Escribir encabezado
	fprintf(file, "-----BEGIN RSA PRIVATE KEY-----\n");

	// Escribir modulus
	fprintf(file, "Modulus: ");
	write_base64(file, (unsigned char*)&public_key->modulus, sizeof(public_key->modulus));
	fprintf(file, "\n");

	// Escribir exponent
	fprintf(file, "Exponent: ");
	write_base64(file, (unsigned char*)&public_key->exponent, sizeof(public_key->exponent));
	fprintf(file, "\n");

	// Escribir pie de página
	fprintf(file, "-----END RSA PRIVATE KEY-----\n");

	fclose(file);
}

int main() {
	struct public_key_class public_key = { 12345, 65537 };
	struct private_key_class private_key = { 12345, 123456789 };

	generate_pem_file("key.pem", &public_key, &private_key);

	return 0;
}
*/