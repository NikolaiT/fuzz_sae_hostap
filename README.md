# Fuzzing SAE in hostap

This fuzzing test with libFuzzer is built on the existing fuzzing test found in `hostap/tests/fuzzing/ap-mgmt`.

Even though both tests use the same fuzzing target function - `ieee802_11_mgmt()` - the existing test cannot
properly target the SAE auth functionality. The reason is that `hostap/tests/fuzzing/ap-mgmt` is compiled without SAE support
and that the `hapd` hostap data structure does not have all required fields set.

```C
	// SAE specific hapd configuration
	os_memcpy(hapd->sae_token_key, "\xe1\x06\x03\xab\x05\x26\x07\x08", 8);
	os_get_reltime(&hapd->last_sae_token_key_update);
	hapd->dot11RSNASAERetransPeriod = 10; //ms
    dl_list_init(&hapd->sae_commit_queue);
	
	hapd->conf->wpa_key_mgmt = WPA_KEY_MGMT_SAE;
	hapd->conf->wpa = WPA_PROTO_RSN;
	hapd->conf->auth_algs = WPA_AUTH_ALG_SAE;
```    

This fuzzzing test supports fuzzing all SAE functionality found in `hostap/src/common/sae.c` and 
MLME logic found in `hostap/src/ap/ieee802_11.c`. 

Therefore, we needed to modify the compilation process in order to provide SAE support.

Another problem was the SAE queuing mechanism. Each new incoming SAE auth commit message is handled only 
after `i*10ms` later, where `i` is the number of pending auth commit messages. This requires a couple of fixes in the 
hostap source code in order to make fuzzing faster.

Furthermore, there is another major problem with memory leaks. There are a couple of `zalloc()'s` in `sae_set_group()` that
allocate memory without freeing. This will abort the fuzzer after a couple of minutes due to too much leaked memory.

## Patch hostap

Before compiling the fuzzer, several locations in hostap need to be patched in order to increase the fuzzing 
speed. All changes are happening in `hostap/src/ieee802_11.c`:

Change `eloop_register_timeout` to 

```C
eloop_register_timeout(0, 0, auth_sae_process_commit,
			       hapd, NULL);
```
                   
in the function `auth_sae_process_commit()` and in the function `auth_sae_queue`.

This will invoke the sae parsing/processing functionality immediately, thus speeding up the fuzzing.

## Installation

First download the most recent version of hostap.

`git clone git://w1.fi/hostap.git`

Then change into the directory with the fuzzing tests

`cd hostap/tests/fuzzing/`

Then download this repository and change into the dir:

`git clone https://github.com/NikolaiT/fuzz_sae_hostap && cd fuzz_sae_hostap`

Change `hostap/tests/fuzzing/rules.include` to 

```
FUZZ_FLAGS ?= -fsanitize=fuzzer,address,signed-integer-overflow,unsigned-integer-overflow
```

Clean and compile the fuzzing test:

```bash

export CC='clang-8'

make clean

make LIBFUZZER=y CONFIG_SAE=y -j4
```

after a couple of moments the fuzzer should be compiled and ready. 

## Fuzz

Now you may run the fuzzer with a command:

```
./sae sae_corpus_2 -detect_leaks=0 -max_len=1050 -print_final_stats=1
```

## Open issues

1. Fix memory leaks that prevent fuzzing for more than 5 minutes. I honestly don't know if this is an issue 
from hostapd or because fuzzing is stopped forcefully after 50 microseconds via

```C
eloop_register_timeout(0, 50, sae_auth_terminate, &ctx, NULL);
```



 
