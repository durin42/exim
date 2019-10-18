../src/Local/Makefile: ../src/OS/Makefile-Linux Makefile
	mkdir -p ../src/Local
	cp ../src/OS/Makefile-Linux ../src/Local/Makefile
	echo BIN_DIRECTORY=/usr/exim/bin >> ../src/Local/Makefile
	echo CONFIGURE_FILE=/usr/exim/configure >> ../src/Local/Makefile
	echo EXIM_USER=ref:exim >> ../src/Local/Makefile
	echo SPOOL_DIRECTORY=/var/spool/exim >> ../src/Local/Makefile
	echo DISABLE_TLS=yes >> ../src/Local/Makefile

doto: ../src/Local/Makefile
	cd ../src/ && FULLECHO= env -u CFLAGS make -e makefile configure
	cd ../src/build-Linux* && FULLECHO= env -u CFLAGS make -e macro_predef
	# hack alert! building exim fails, but we get all the .o files
	# we need as a side effect.
	cd ../src/build-Linux* && FULLECHO= make -e exim || true

parse_extract_address_fuzzer: parse_extract_address.cc doto
	rm ../src/build-Linux*/macro_*.o ../src/build-Linux*/macro-*.o
	find ../src/build-Linux* -name '*.o'
	$(CXX) $(CXXFLAGS) -I. -I$$(ls -d ../src/build-Linux*/) \
	    parse_extract_address.cc \
	    ../src/build-Linux*/*.o ../src/build-Linux*/lookups/*.o \
	    ../src/build-Linux*/*/*.o \
	    -o $$OUT/parse_extract_address_fuzzer \
	    -lresolv -lpcre -lcrypt -lm -ldb \
	    -lFuzzingEngine

all: parse_extract_address_fuzzer

clean:
	$(RM) *.o *_fuzzer

.PHONY: all clean doto
