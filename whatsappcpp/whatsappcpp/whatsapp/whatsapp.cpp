#include "whatsapp.h"
#include <iostream>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include "../curve/curve.h"

//whatsapp internal public key, 32 bytes
const unsigned char whatsapp_publickey[32] = {
	0x8e, 0x8c, 0x0f, 0x74, 0xc3, 0xeb, 0xc5, 0xd7,
	0xa6, 0x86, 0x5c, 0x6c, 0x3c, 0x84, 0x38, 0x56,
	0xb0, 0x61, 0x21, 0xcc, 0xe8, 0xea, 0x77, 0x4d,
	0x22, 0xfb, 0x6f, 0x12, 0x25, 0x12, 0x30, 0x2d
};

void getkeys(std::string* pubkey, std::string* agreement) {
	ec_public_key wa_public_key;
	memcpy(wa_public_key.data, whatsapp_publickey, sizeof(whatsapp_publickey));
	ec_key_pair* keypair;
	int ret = curve_generate_key_pair(&keypair);



	uint8_t* agreement_bytes = NULL;
	ret = curve_calculate_agreement(&agreement_bytes, &wa_public_key, keypair->private_key);

	*pubkey = std::string((const char*)keypair->public_key->data, sizeof(keypair->public_key->data));
	*agreement = std::string((const char*)agreement_bytes, 32);

	free(agreement_bytes);
}
void replaceAll(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}


void test1() {
	std::string total;
	std::string pubkey, agreement;
	//get keypairs
	getkeys(&pubkey, &agreement);
	total.append(pubkey);
	int ret = 0;
	const unsigned char iv[12] = { 0 };
	unsigned char encrypt_output[1000] = { 0 };
	unsigned char decrypt_output[1000] = { 0 };
	mbedtls_gcm_context ctx;
	mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

	//https://v.whatsapp.net/v2/exist?ENC=gBYVneQyuhNFEXPsj3g0k0htJ3KNZTdvIc3cr6Wl024g805AHQr43L2z0Eqr2UUhxNntc481mkZlb_pVeB-qPxxnvyRcYMrcY5HJVSAuFpRYRnWHn7kWi8J7O7q9qk9zqdeg6SALPOSmEFktEWrGCxUvt0RKuQf-WknlhURQooJmHveYMoS32DCq9ZDa6OG9RjxpcMulrV3JU1vj97s2Mt4smbGe8P0TMMKu8dEbgM-94m5BonNrnhoDneMeujIevpfR7TgY_bX8cNsnaTl8ZdfPLtsSBojRuTDhlKPSOxK5ebHqt1pe6n67Elqgv9zYorNQ2JtvGFPgWJCo5N4FrMwxcTGE9NjqgbLKqlaXspdhy_oVHSNh7fBhpoIc2mnGjxVrXo_NanPfz7jEJFOK0o2fVE-Z32P-68wWM1JU4LISIQVQK09BIoHJ-8u8OZ0tXcZOTK14aZNqtWAciOGvellOl8ewqdwBmTyexDxi0GeW4aRRtHFIQAtLxt4Qgx2ZNrXBnuui_SUgJe5o3nJcPJp0cQXH8xLJ-gbuGRO_M-VnppG5sNAc8pC-LLBiliLJ85YM4N5TRdxa51_mMOhSjs9meu2Vx3IvmfeZe6NPdU8ngizIuf_GBvtRgSs_HNCsUokAeB69_2JveEGGmui7wZhRSs44WHIiT3kCTJF1J7R1aTZbcYY4cwO17p_pI7Iupmm1orTtrUfLYyrAksWvBvFjfRo2YJS9CJvHzvs2ucm_g8h_XcT6R56d9wqOC0yxt0aLQJ64qmoLgbsSY1bfmpXeiRo_A7GJLIra0Fs-8PNMKjfi_UIH1DYfuC6ehYOB44StpjlMGTClCrg0X4wdVB8Fp8JSHIQp6eqKbXLbH8Uwk0BCeXWdrkpzcyR5AYXqxT-tzDw8xCN8MM9f7bWXjB5I6xPtEy5DtD7tQjQkuEPM2j8tjy5i7m7BuRC8WZmM-Cyylfiq47b9k7-HDW0F5ARyxe-a0cVo_W_sOi6wcZKOgq4mSJZ81eG2Tl3FvyXEXpUIE8qEzamZJVygFrOgrFwdkagekDUVUicRhSutVd-OZ_Jry6l3I32Qgz54T8rC3QpuQRl6ez_0eABFYTea-Qc21VFRex9rdw
	const char* testdata = "read_phone_permission_granted=0&lc=CN&offline_ab=%7B%22exposure%22%3A%5B%5D%2C%22metrics%22%3A%7B%7D%7D&in=13512345555&lg=zh&id=%5CMv%0DX%A4%B5%1Eh2%A2%3D%16q%D6%26%98Q%A5~&e_regid=RVThAw&mistyped=7&authkey=IY1R2WT2aWEmntvJuZdKx1AVaH_eHrkLzny_iBOdVHo&e_skey_sig=fFli5q6K6I7UQxZUTr-nKn0wrmKdOK2slKizAbO7jcIrONNsQqB6GY6ozWsDHOE2u1Gae4EBPAGbznn1l4dhCg&token=zTk5AlKokMk6j2CWlDvw177fRuc%3D&expid=Lb_A2F98SI-22AwWtan39A&e_ident=daJIPw26ymfRL-KusnG_Mm3JlN8GwY7l10fZHGCbHWw&rc=0&simnum=0&sim_state=1&client_metrics=%7B%22attempts%22%3A143%2C%22was_activated_from_stub%22%3Afalse%7D&cc=86&e_skey_id=AAAA&fdid=8658c144-14d5-4bee-8ead-f904b94ded30&e_skey_val=mWQTsNG1de6dORIMN5XGHmqC-plwpDZtsM2MRlaWVEY&network_radio_type=1&hasinrc=1&network_operator_name=&sim_operator_name=&e_keytype=BQ&pid=30184";
	int datalen = strlen(testdata);

	mbedtls_gcm_init(&ctx);
	ret = mbedtls_gcm_setkey(&ctx, cipher, (const unsigned char*)agreement.data(), 8 * 32);
	ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
		datalen, iv, sizeof(iv),
		NULL, 0,
		(const unsigned char*)testdata, encrypt_output, 16, encrypt_output + datalen);


	total.append(std::string((const char*)encrypt_output, datalen + 16));

	unsigned char base64out[2000] = { 0 };
	size_t outlen = 0;
	mbedtls_base64_encode(base64out, 2000, &outlen, (const unsigned char*)total.data(), total.length());


	std::string urlsafe = std::string((const char*)base64out, outlen);
	replaceAll(urlsafe, "/", "_");
	replaceAll(urlsafe, "+", "-");
	replaceAll(urlsafe, "=", "");

	// 	ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT,
	// 		datalen, iv, sizeof(iv),
	// 		NULL, 0,
	// 		(const unsigned char*)encrypt_output, decrypt_output, 16, decrypt_output + datalen);

	mbedtls_gcm_free(&ctx);

	return;
}