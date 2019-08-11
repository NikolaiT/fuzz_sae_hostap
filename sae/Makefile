all: sae
include ../rules.include

ifdef CONFIG_SAE
CFLAGS += -DCONFIG_SAE
OBJS += $(SRC)/common/sae.o
NEED_ECC=y
NEED_DH_GROUPS=y
NEED_AP_MLME=y
NEED_DRAGONFLY=y
endif

ifdef NEED_ECC
CFLAGS += -DCONFIG_ECC
endif

ifdef NEED_DH_GROUPS
OBJS += $(SRC)/crypto/dh_groups.o
endif
ifdef NEED_DH_GROUPS_ALL
CFLAGS += -DALL_DH_GROUPS
endif
ifdef CONFIG_INTERNAL_DH_GROUP5
ifdef NEED_DH_GROUPS
OBJS += $(SRC)/crypto/dh_group5.o
endif
endif

ifdef NEED_AP_MLME
OBJS += $(SRC)/ap/wmm.o
OBJS += $(SRC)/ap/ap_list.o
OBJS += $(SRC)/ap/ieee802_11.o
OBJS += $(SRC)/ap/hw_features.o
OBJS += $(SRC)/ap/dfs.o
CFLAGS += -DNEED_AP_MLME
endif
ifdef CONFIG_IEEE80211N
OBJS += $(SRC)/ap/ieee802_11_ht.o
endif

ifdef NEED_DRAGONFLY
OBJS += $(SRC)/common/dragonfly.o
endif


ifndef CONFIG_TLS
CONFIG_TLS=openssl
endif

ifeq ($(CONFIG_TLS), openssl)
CONFIG_CRYPTO=openssl
ifdef TLS_FUNCS
OBJS += $(SRC)/crypto/tls_openssl.o
OBJS += $(SRC)/crypto/tls_openssl_ocsp.o
LIBS += -lssl
endif
OBJS += $(SRC)/crypto/crypto_openssl.o
HOBJS += $(SRC)/crypto/crypto_openssl.o
ifdef NEED_FIPS186_2_PRF
OBJS += $(SRC)/crypto/fips_prf_openssl.o
endif
NEED_SHA256=y
NEED_TLS_PRF_SHA256=y
LIBS += -lcrypto
LIBS_h += -lcrypto
LIBS_n += -lcrypto
ifdef CONFIG_TLS_ADD_DL
LIBS += -ldl
LIBS_h += -ldl
endif
ifndef CONFIG_TLS_DEFAULT_CIPHERS
CONFIG_TLS_DEFAULT_CIPHERS = "DEFAULT:!EXP:!LOW"
endif
CFLAGS += -DTLS_DEFAULT_CIPHERS=\"$(CONFIG_TLS_DEFAULT_CIPHERS)\"
endif

CFLAGS += -DCONFIG_WNM
CFLAGS += -DCONFIG_INTERWORKING
CFLAGS += -DCONFIG_GAS
CFLAGS += -DCONFIG_HS20
CFLAGS += -DIEEE8021X_EAPOL
CFLAGS += -DNEED_AP_MLME
CFLAGS += -DCONFIG_AIRTIME_POLICY
CFLAGS += -DCONFIG_SAE

LIBS += $(SRC)/common/libcommon.a
LIBS += $(SRC)/crypto/libcrypto.a
LIBS += $(SRC)/tls/libtls.a
LIBS += $(SRC)/wps/libwps.a
LIBS += $(SRC)/eap_server/libeap_server.a
LIBS += $(SRC)/eap_common/libeap_common.a
LIBS += $(SRC)/l2_packet/libl2_packet.a
LIBS += $(SRC)/ap/libap.a
LIBS += $(SRC)/eapol_auth/libeapol_auth.a
LIBS += $(SRC)/radius/libradius.a
LIBS += $(SRC)/utils/libutils.a

ELIBS += $(SRC)/crypto/libcrypto.a
ELIBS += $(SRC)/tls/libtls.a

sae: sae.o $(OBJS) $(LIBS)
	$(LDO) $(LDFLAGS) -o $@ $^ $(LIBS) $(ELIBS)

clean:
	$(MAKE) -C $(SRC) clean
	rm -f ap-mgmt *~ *.o *.d ../*~ ../*.o ../*.d

-include $(OBJS:%.o=%.d)
