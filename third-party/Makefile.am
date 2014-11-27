if BUILD_UTP
  UTP_DIR = libutp
endif
if BUILD_MINIUPNP
  MINIUPNP_DIR = miniupnp
endif
if BUILD_NATPMP 
  NATPMP_DIR = libnatpmp 
endif 
if BUILD_B64
  B64_DIR = libb64
endif

SUBDIRS = \
  dht \
  $(NATPMP_DIR) \
  $(MINIUPNP_DIR) \
  $(UTP_DIR) \
  $(B64_DIR)

EXTRA_DIST = \
  macosx-libevent-config.h \
  macosx-libevent-event-config.h
