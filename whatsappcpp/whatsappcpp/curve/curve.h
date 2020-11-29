#pragma once

#include <stdint.h>
#include <stddef.h>
#define DJB_KEY_LEN 32


struct ec_public_key
{
	uint8_t data[DJB_KEY_LEN];
};

struct ec_private_key
{
	uint8_t data[DJB_KEY_LEN];
};

struct ec_key_pair
{
	ec_public_key* public_key;
	ec_private_key* private_key;
};


int curve_generate_private_key(ec_private_key** private_key);
int curve_generate_public_key(ec_public_key** public_key, const ec_private_key* private_key);
int ec_key_pair_create(ec_key_pair** key_pair, ec_public_key* public_key, ec_private_key* private_key);
int curve_generate_key_pair(ec_key_pair** key_pair);
int curve_calculate_agreement(uint8_t** shared_key_data, const ec_public_key* public_key, const ec_private_key* private_key);