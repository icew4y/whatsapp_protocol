#include "curve.h"
#include <malloc.h>
#include <openssl/rand.h>
#include "curve25519-donna.h"


int test_random_generator(uint8_t* data, size_t len)
{
	if (RAND_bytes(data, len)) {
		return 0;
	}
	else {
		return -1;
	}
}

int curve_generate_private_key(ec_private_key** private_key)
{
	int result = 0;
	ec_private_key* key = 0;


	key = (ec_private_key *)malloc(sizeof(ec_private_key));
	if (!key) {
		result = -1;
		goto complete;
	}


	result = test_random_generator(key->data, DJB_KEY_LEN);
	if (result < 0) {
		goto complete;
	}

	key->data[0] &= 248;
	key->data[31] &= 127;
	key->data[31] |= 64;

complete:
	if (result < 0) {
		if (key) {
			free(key);
		}
	}
	else {
		*private_key = key;
	}

	return result;
}

int curve_generate_public_key(ec_public_key** public_key, const ec_private_key* private_key)
{
	static const uint8_t basepoint[32] = { 9 };
	int result = 0;

	ec_public_key* key = (ec_public_key*)malloc(sizeof(ec_public_key));
	if (!key) {
		return -1;
	}


	result = curve25519_donna(key->data, private_key->data, basepoint);

	if (result == 0) {
		*public_key = key;
		return 0;
	}
	else {
		if (key) {
			free(key);
		}
		return -1;
	}
}

int ec_key_pair_create(ec_key_pair** key_pair, ec_public_key* public_key, ec_private_key* private_key)
{
	ec_key_pair* result = (ec_key_pair*)malloc(sizeof(ec_key_pair));
	if (!result) {
		return -1;
	}

	result->public_key = public_key;
	result->private_key = private_key;
	*key_pair = result;

	return 0;
}

int curve_generate_key_pair(ec_key_pair** key_pair)
{
	int result = 0;
	ec_key_pair* pair_result = 0;
	ec_private_key* key_private = 0;
	ec_public_key* key_public = 0;


	result = curve_generate_private_key(&key_private);
	if (result < 0) {
		goto complete;
	}

	result = curve_generate_public_key(&key_public, key_private);
	if (result < 0) {
		goto complete;
	}

	result = ec_key_pair_create(&pair_result, key_public, key_private);
	if (result < 0) {
		goto complete;
	}

	*key_pair = pair_result;

complete:

	return result;
}



int curve_calculate_agreement(uint8_t** shared_key_data, const ec_public_key* public_key, const ec_private_key* private_key)
{
	uint8_t* key = 0;
	int result = 0;

	if (!public_key || !private_key) {
		return -1;
	}

	key = (uint8_t*)malloc(DJB_KEY_LEN);
	if (!key) {
		return -1;
	}

	result = curve25519_donna(key, private_key->data, public_key->data);

	if (result == 0) {
		*shared_key_data = key;
		return DJB_KEY_LEN;
	}
	else {
		if (key) {
			free(key);
		}
		return -1;
	}
}