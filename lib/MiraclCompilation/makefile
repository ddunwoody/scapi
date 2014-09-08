# settings
MIRDEF=$(ARCH)bit/$(MIRACL_TARGET_LANG)/mirdef.h

MRMULDV_SOURCE=mrmuldv.c.o
#ifeq ($(uname_S),Linux)
MRMULDV_EXT=gcc
ifeq ($(ARCH),64)
	MRMULDV_EXT=g64
endif
#endif

#ifeq ($(uname_S),Darwin)
#	MRMULDV_SOURCE=mrmuldv.asm.o
#	MRMULDV_EXT=s32
#	ifeq ($(ARCH),64)
#		MRMULDV_EXT=s64
#	endif
#endif

# compilation options
CXX=g++
CC=gcc
ifeq ($(MIRACL_TARGET_LANG),cpp)
	CC=$(CXX)
endif
AR=ar
override CFLAGS=-fPIC -m64 -O2
override CXXFLAGS=-fPIC -m64 -O2

# sources
SOURCES = mrcore.c mrarth0.c mrarth1.c mrarth2.c mralloc.c mrsmall.c mrio1.c mrio2.c mrgcd.c mrjack.c mrxgcd.c mrarth3.c mrbits.c mrrand.c mrprime.c mrcrt.c mrscrt.c mrmonty.c mrpower.c mrsroot.c mrcurve.c mrfast.c mrshs.c mrshs256.c mrshs512.c mrsha3.c mrfpe.c mraes.c mrgcm.c mrlucas.c mrzzn2.c mrzzn2b.c mrzzn3.c mrzzn4.c mrecn2.c mrstrong.c mrbrick.c mrebrick.c mrec2m.c mrgf2m.c mrflash.c mrfrnd.c mrdouble.c mrround.c mrbuild.c mrflsh1.c mrpi.c mrflsh2.c mrflsh3.c mrflsh4.c mrmuldv.c
CPP_SOURCES = big.cpp zzn.cpp ecn.cpp ec2.cpp crt.cpp flash.cpp polymod.cpp poly.cpp

OBJ_FILES = $(SOURCES:.c=.o)
CPP_OBJ_FILES = $(CPP_SOURCES:.cpp=.opp)

ALL_OBJ_FILES = $(OBJ_FILES)
ifeq ($(MIRACL_TARGET_LANG),cpp)
	ALL_OBJ_FILES += $(CPP_OBJ_FILES)
endif

libmiracl.a: mirdef.h $(ALL_OBJ_FILES)
	$(AR) crv $@ $(ALL_OBJ_FILES)

mirdef.h:
	cp $(MIRDEF) mirdef.h

mrmuldv.asm.o:
	cp mrmuldv.$(MRMULDV_EXT) mrmuldv.s
	as mrmuldv.s -o $@

mrmuldv.c.o:
	cp mrmuldv.$(MRMULDV_EXT) mrmuldv.c
	$(CC) $(CFLAGS) -c mrmuldv.c -o $@

mrmuldv.o: $(MRMULDV_SOURCE)
	cp $< $@

%.o: %.c mirdef.h
	$(CC) $(CFLAGS) -c $<

# we use the *.opp extension for object files of the CPP modules
# so we can distinguish them and use general build rules
%.opp: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install:
	install -d $(prefix)/include/miracl
	install -d $(prefix)/lib
	install -m 0644 libmiracl.a $(prefix)/lib
	install -m 0644 *.h $(prefix)/include/miracl

clean:
	rm -f *.a
	rm -f *.o
	rm -f *.opp
	rm -f mirdef.h
	rm -f mrmuldv.c
