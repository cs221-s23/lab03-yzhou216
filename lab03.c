#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "passwords.h"
#include "sha256.h"

#define DIG_BIN_LEN 32
#define DIG_STR_LEN ((DIG_BIN_LEN * 2))

/* define the length of passwords dictionary */
#define DICT_LEN (sizeof(passwords) / sizeof(passwords[0]))
#define PASSWD_MAX_LEN 64

void sha256(char *dest, char *src)
{
	/* zero out the sha256 context */
	struct sha256_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	/* zero out the binary version of the hash digest */
	unsigned char dig_bin[DIG_BIN_LEN];
	memset(dig_bin, 0, DIG_BIN_LEN);

	/* zero out the string version of the hash digest */
	memset(dest, 0, DIG_STR_LEN + 1);

	/* compute the binary hash digest */
	__sha256_init_ctx(&ctx);
	__sha256_process_bytes(src, strlen(src), &ctx);
	__sha256_finish_ctx(&ctx, dig_bin);

	/* convert it into a string of hexadecimal digits */
	for (int i = 0; i < DIG_BIN_LEN; i++) {
		snprintf(dest, 3, "%02x", dig_bin[i]);
		dest += 2;
	}
}

char *dig(char *str)
{
	char *res = (char *) malloc((DIG_STR_LEN + 1) * sizeof(char));
	sha256(res, str);
	return res;
}

char *leet(char *str)
{
	char *res = (char *) malloc((strlen(str) + 1) * sizeof(char));
	for (int i = 0; i < strlen(str); i++) {
		switch (str[i]) {
			case 'o':
				res[i] = '0';
				break;
			case 'e':
				res[i] = '3';
				break;
			case 'i':
				res[i] = '!';
				break;
			case 'a':
				res[i] = '@';
				break;
			case 'h':
				res[i] = '#';
				break;
			case 's':
				res[i] = '$';
				break;
			case 't':
				res[i] = '+';
				break;
			default:
				res[i] = str[i];
		}
	}
	return res;
}

char *add_one(char *str)
{
	/*
	 * Allocate memory for the result to be one byte more than the source
	 * string for the addition of the charactor '1' at the end.
	 */
	char *res = (char *) malloc((strlen(str) + 2) * sizeof(char));
	/* length of the res string excluding the NULL terminator */
	int res_len = strlen(str) + 1;
	memset(res, 0, res_len + 1);
	strncpy(res, str, res_len);
	strncat(res, "1", res_len);
	return res;
}

struct pairs {
	char passwd[PASSWD_MAX_LEN + 1];
	char passwd_dig[DIG_STR_LEN + 1];

	char leet_passwd[PASSWD_MAX_LEN + 1];
	char leet_passwd_dig[DIG_STR_LEN + 1];

	char add_one_passwd[PASSWD_MAX_LEN + 2];
	char add_one_passwd_dig[DIG_STR_LEN + 2];
};

void write_dict_csv(struct pairs *dict, FILE *fp, int size) {
	for (int i = 0; i < size; i++) {
		fprintf(fp, "%s,%s\n%s,%s\n%s,%s\n",
			    dict[i].passwd, dict[i].passwd_dig,
			    dict[i].leet_passwd, dict[i].leet_passwd_dig,
			    dict[i].add_one_passwd, dict[i].add_one_passwd_dig);
	}
}

int main(int argc, char **argv)
{
	if (argc != 1 && argc != 2) {
		printf("invalid arguments\n");
		exit(-1);
	}

	char *fpath = "dict.txt";
	FILE *fp;

	if (argc == 1)
		goto fcheck;

	fp = fopen(fpath, "r");
	if (fp == NULL) {
		printf("dictionary not found\n", fpath);
		exit(-1);
	}

	/* create dictionary struct array to be read */
	struct pairs r_dict[DICT_LEN];
	for (int i = 0; i <= DICT_LEN; i++) {
		fread(&r_dict[i], sizeof(r_dict), 1, fp);

		if (!strcmp(r_dict[i].passwd_dig, argv[1])) {
			printf("%s\n", r_dict[i].passwd);
			return 0;
		}

		if (!strcmp(r_dict[i].leet_passwd_dig, argv[1])) {
			printf("%s\n", r_dict[i].leet_passwd);
			return 0;
		}

		if (!strcmp(r_dict[i].add_one_passwd_dig, argv[1])) {
			printf("%s\n", r_dict[i].add_one_passwd);
			return 0;
		}
	}
	fclose(fp);

	printf("not found\n");
	return 0;

fcheck:
	/* check if file exists */
	if (!access(fpath, F_OK) && argc == 1) {
		printf("dictionary exists\n");
		return 0;
	}

	/* create dictionary struct array to be written */
	struct pairs w_dict[DICT_LEN];
	char *dig_str;
	char *leet_str;
	char *add_one_str;
	for (int i = 0; i < DICT_LEN; i++) {
		dig_str = dig(passwords[i]);
		memset(w_dict[i].passwd, 0, PASSWD_MAX_LEN + 1);
		memset(w_dict[i].passwd_dig, 0, DIG_STR_LEN + 1);
		strncpy(w_dict[i].passwd, passwords[i], PASSWD_MAX_LEN);
		strncpy(w_dict[i].passwd_dig, dig_str, DIG_STR_LEN);
		free(dig_str);

		leet_str = leet(passwords[i]);
		dig_str = dig(leet_str);
		memset(w_dict[i].leet_passwd, 0, PASSWD_MAX_LEN + 1);
		memset(w_dict[i].leet_passwd_dig, 0, DIG_STR_LEN + 1);
		strncpy(w_dict[i].leet_passwd, leet_str, PASSWD_MAX_LEN);
		strncpy(w_dict[i].leet_passwd_dig, dig_str, DIG_STR_LEN);
		free(leet_str);
		free(dig_str);

		add_one_str = add_one(passwords[i]);
		dig_str = dig(add_one_str);
		memset(w_dict[i].add_one_passwd, 0, PASSWD_MAX_LEN + 2);
		memset(w_dict[i].add_one_passwd_dig, 0, DIG_STR_LEN + 1);
		strncpy(w_dict[i].add_one_passwd,
			add_one_str,
			PASSWD_MAX_LEN + 1);
		strncpy(w_dict[i].add_one_passwd_dig, dig_str, DIG_STR_LEN);
		free(add_one_str);
		free(dig_str);
	}

	/* create file */
	fp = fopen(fpath, "w");
	if (fp == NULL) {
		printf("%s open error\n", fpath);
		exit(-1);
	}

	/* write struct to file */
	for (int i = 0; i < DICT_LEN; i++) {
		fwrite(&w_dict[i], sizeof(w_dict[0]), 1, fp);
	}

	/* write human-readable csv dictionary */
	fp = fopen("dict.csv", "w");
	write_dict_csv(w_dict, fp, DICT_LEN);
	fclose(fp);

	printf("dictionary built\n");
	return 0;
}
