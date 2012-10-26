OPUS=opus-1.0.1
OGG=libogg-1.3.0
VORBIS=libvorbis-1.3.3
SHOUT=libshout-2.3.1

BASE=../../../..

OPUS_DIR=$(switch_srcdir)/libs/$(OPUS)
OPUS_BUILDDIR=$(switch_builddir)/libs/$(OPUS)
OPUSLA=$(OPUS_BUILDDIR)/libopus.la
OPUS_CFLAGS=-I$(OPUS_DIR)/include
OPUS_LIBS=$(OPUSLA)

OGG_DIR=$(switch_srcdir)/libs/$(OGG)
OGG_BUILDDIR=$(switch_builddir)/libs/$(OGG)
OGGLA=$(OGG_BUILDDIR)/src/libogg.la
OGG_CFLAGS=-I$(OGG_DIR)/include -I$(OGG_BUILDDIR)/include
OGG_LIBS=$(OGGLA)

VORBIS_DIR=$(switch_srcdir)/libs/$(VORBIS)
VORBIS_BUILDDIR=$(switch_builddir)/libs/$(VORBIS)
VORBISLA=$(VORBIS_BUILDDIR)/lib/libvorbis.la
VORBIS_CFLAGS=-I$(VORBIS_DIR)/include
VORBIS_LIBS=$(VORBISLA)
VORBISENCLA=$(VORBIS_BUILDDIR)/lib/libvorbisenc.la
VORBISENC_LIBS=$(VORBISENCLA)

SHOUT_DIR=$(switch_srcdir)/libs/$(SHOUT)
SHOUT_BUILDDIR=$(switch_builddir)/libs/$(SHOUT)
SHOUTLA=$(SHOUT_BUILDDIR)/src/libshout.la
SHOUT_CFLAGS=-I$(SOUD_DIR)/include -I$(SHOUT_BUILDDIR)/include
SHOUT_LIBS=$(SHOUTLA)

LOCAL_CFLAGS=$(OPUS_CFLAGS) $(OGG_CFLAGS) $(VORBIS_CFLAGS) $(SHOUT_CFLAGS)
LOCAL_LIBADD=$(OPUS_LIBS) $(SHOUT_LIBS) $(VORBISENC_LIBS) $(VORBIS_LIBS) $(OGG_LIBS)
#LOCAL_LDFLAGS=`cat $(SHOUT_BUILDDIR)/Makefile | grep SPEEX_LIBS | sed -e 's|^SPEEX_LIBS =||'`  `cat $(SHOUTLA) | grep dependency_libs  | sed -e 's|^dependency_libs=||' | sed -e "s|'||g"`

include $(BASE)/build/modmake.rules

$(MODNAME).lo: $(LOCAL_LIBADD)

$(OPUS_DIR):
	$(GETLIB) $(OPUS).tar.gz

$(OPUS_BUILDDIR)/Makefile: $(OPUS_DIR)
	mkdir -p $(OPUS_BUILDDIR)
	cd $(OPUS_BUILDDIR) && $(DEFAULT_VARS) $(OPUS_DIR)/configure $(DEFAULT_ARGS) --srcdir=$(OPUS_DIR)
	$(TOUCH_TARGET)

$(OPUSLA): $(OPUS_DIR)/Makefile
	cd $(OPUS_BUILDDIR) && $(MAKE)
	$(TOUCH_TARGET)


$(OGG_DIR):
	$(GETLIB) $(OGG).tar.gz

$(OGG_BUILDDIR)/Makefile: $(OGG_DIR)
	mkdir -p $(OGG_BUILDDIR)
	cd $(OGG_BUILDDIR) && $(DEFAULT_VARS) $(OGG_DIR)/configure $(DEFAULT_ARGS) --srcdir=$(OGG_DIR)
	$(TOUCH_TARGET)

$(OGGLA): $(OGG_BUILDDIR)/Makefile
	cd $(OGG_BUILDDIR) && $(MAKE)
	$(TOUCH_TARGET)


$(VORBIS_DIR):
	$(GETLIB) $(VORBIS).tar.gz

$(VORBIS_BUILDDIR)/Makefile: $(VORBIS_DIR) $(OGGLA)
	mkdir -p $(VORBIS_BUILDDIR)
	cd $(VORBIS_BUILDDIR) && $(DEFAULT_VARS) $(VORBIS_DIR)/configure $(DEFAULT_ARGS) --srcdir=$(VORBIS_DIR) OGG_CFLAGS="$(OGG_CFLAGS)" OGG_LIBS="$(OGG_LIBS)"
	$(TOUCH_TARGET)

$(VORBISLA): $(VORBIS_BUILDDIR)/Makefile
	cd $(VORBIS_BUILDDIR) && $(MAKE)
	$(TOUCH_TARGET)

$(SHOUT_DIR):
	$(GETLIB) $(SHOUT).tar.gz

$(SHOUT_BUILDDIR)/Makefile: $(SHOUT_DIR) $(OGGLA) $(VORBISLA)
	mkdir -p $(SHOUT_BUILDDIR)
	cd $(SHOUT_BUILDDIR) && $(DEFAULT_VARS) $(SHOUT_DIR)/configure $(DEFAULT_ARGS) --srcdir=$(SHOUT_DIR) --disable-theora --disable-speex VORBIS_CFLAGS="$(OGG_CFLAGS) $(VORBIS_CFLAGS)" VORBIS_LIBS="$(VORBIS_LIBS) $(OGG_LIBS)"
	$(TOUCH_TARGET)

$(SHOUTLA): $(SHOUT_BUILDDIR)/Makefile
	cd $(SHOUT_BUILDDIR) && $(MAKE)
	$(TOUCH_TARGET)



