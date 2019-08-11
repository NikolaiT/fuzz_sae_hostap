/*
 * hostapd - SAE authentication fuzzer
 * Copyright (c) 2019, Nikolai Tschacher <nikolai@tschacher.ch>
 * Copyright (c) 2015-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Compile with:
 * make clean
 * make LIBFUZZER=y
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "ap/hostapd.h"
#include "ap/hw_features.h"
#include "ap/ieee802_11.h"
#include "ap/sta_info.h"
#include "ap/ap_list.h"
#include "../fuzzer-common.h"

#include "common/sae.h"
#include "utils/list.h"
#include "crypto/crypto.h"


const struct wpa_driver_ops *const wpa_drivers[] =
{
	NULL
};


struct arg_ctx {
	const u8 *data;
	size_t data_len;
	struct hostapd_iface iface;
	struct hostapd_data hapd;
	struct wpa_driver_ops driver;
	struct hostapd_config iconf;
	struct hostapd_bss_config conf;
};


static void sae_auth_terminate(void *eloop_data, void *user_ctx) {
  eloop_terminate();
}


static void test_send_sae_mgmt(void *eloop_data, void *user_ctx)
{
  struct arg_ctx *ctx = eloop_data;
  struct hostapd_frame_info fi;

  os_memset(&fi, 0, sizeof(fi));

  unsigned char sae_mgmt_frame[] = {
      0xb0, 0x00, 0x3a, 0x01, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0xb0, 0x04,
      0x03, 0x00 // 0x01, 0x00, 0x00, 0x00,
  };
  unsigned int sae_mgmt_frame_len = 26;

  size_t bufSize = ctx->data_len + sae_mgmt_frame_len;
  unsigned char fuzzData[bufSize];
  memset(fuzzData, 0, bufSize);
  memcpy(fuzzData, sae_mgmt_frame, sae_mgmt_frame_len);
  memcpy(fuzzData + sae_mgmt_frame_len, ctx->data, ctx->data_len);

  ieee802_11_mgmt(
    &ctx->hapd,
    fuzzData,
    bufSize,
    &fi
  );

  /* Give SAE 10 microseconds to process the fuzzed frame.
   * This requires to patch 2 timeouts in ieee802_11.c:
   *
   * eloop_register_timeout(0, 0, auth_sae_process_commit,
			       hapd, NULL);
   * in auth_sae_process_commit()
   *
   * and
   *
	 * eloop_register_timeout(0, 0, auth_sae_process_commit,
			       hapd, NULL);

   * in auth_sae_queue()
   */
  eloop_register_timeout(0, 100, sae_auth_terminate, &ctx, NULL);
}

static struct hostapd_hw_modes * gen_modes(void)
{
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *chan;

	mode = os_zalloc(sizeof(struct hostapd_hw_modes));
	if (!mode)
		return NULL;

	mode->mode = HOSTAPD_MODE_IEEE80211G;
	chan = os_zalloc(sizeof(struct hostapd_channel_data));
	if (!chan) {
		os_free(mode);
		return NULL;
	}
	chan->chan = 1;
	chan->freq = 2412;
	mode->channels = chan;
	mode->num_channels = 1;

	mode->rates = os_zalloc(sizeof(int));
	if (!mode->rates) {
		os_free(chan);
		os_free(mode);
		return NULL;
	}
	mode->rates[0] = 10;
	mode->num_rates = 1;

	return mode;
}


static int init_hapd(struct arg_ctx *ctx)
{
	struct hostapd_data *hapd = &ctx->hapd;
	struct sta_info *sta;
	struct hostapd_bss_config *bss;

	hapd->driver = &ctx->driver;
	os_memcpy(hapd->own_addr, "\x02\x00\x00\x00\x02\x00", ETH_ALEN); // 02:00:00:00:02:00
	hapd->iface = &ctx->iface;
	hapd->iface->conf = hostapd_config_defaults();
	if (!hapd->iface->conf)
		return -1;
	hapd->iface->hw_features = gen_modes();
	hapd->iface->num_hw_features = 1;
	hapd->iface->current_mode = hapd->iface->hw_features;
	hapd->iconf = hapd->iface->conf;
	hapd->iconf->hw_mode = HOSTAPD_MODE_IEEE80211G;
	hapd->iconf->channel = 1;
	bss = hapd->conf = hapd->iconf->bss[0];
	hostapd_config_defaults_bss(hapd->conf);

	// SAE specific hapd configuration
	os_memcpy(hapd->sae_token_key, "\xe1\x06\x03\xab\x05\x26\x07\x08", 8);
	os_get_reltime(&hapd->last_sae_token_key_update);
	hapd->dot11RSNASAERetransPeriod = 10; //ms
  dl_list_init(&hapd->sae_commit_queue);
	
	hapd->conf->wpa_key_mgmt = WPA_KEY_MGMT_SAE;
	hapd->conf->wpa = WPA_PROTO_RSN;
	hapd->conf->auth_algs = WPA_AUTH_ALG_SAE;

	os_memcpy(bss->ssid.ssid, "WPA3-Network", 12);
	bss->ssid.ssid_len = 12;
	bss->ssid.ssid_set = 1;

	sta = ap_sta_add(hapd, (u8 *) "\x02\x00\x00\x00\x00\x00"); // 02:00:00:00:00:00
	if (sta)
		sta->flags |= WLAN_STA_ASSOC | WLAN_STA_WMM;

	return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct arg_ctx ctx;

	wpa_fuzzer_set_debug_level();

	if (os_program_init())
		return 0;

	if (eloop_init()) {
		wpa_printf(MSG_ERROR, "Failed to initialize event loop");
		return 0;
	}

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.data = data;
	ctx.data_len = size;

	if (init_hapd(&ctx))
		goto fail;

	eloop_register_timeout(0, 0, test_send_sae_mgmt, &ctx, NULL);

	wpa_printf(MSG_DEBUG, "Starting eloop");
	eloop_run();
	wpa_printf(MSG_DEBUG, "eloop done");
	hostapd_free_stas(&ctx.hapd);
	hostapd_free_hw_features(ctx.hapd.iface->hw_features,
				 ctx.hapd.iface->num_hw_features);

fail:
	hostapd_config_free(ctx.hapd.iconf);
	ap_list_deinit(&ctx.iface);
	eloop_destroy();
	os_program_deinit();

	return 0;
}
