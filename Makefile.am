SUBDIRS = . src

if WITH_TEST
SUBDIRS += test

all-local:
	(cd $(top_srcdir)/contrib/gtest-1.7.0; make)
endif

clean-local:
	${RM} -f *~

install-data-local:
	@if [ -z "${LIGHTTPD_LOCATION}" ]; then \
		echo "not specified lighttpd location"; \
		exit 0; \
	fi
	@if [ ! -e ${LIGHTTPD_LOCATION} ]; then \
		echo "\"${LIGHTTPD_LOCATION}\" does not exist"; \
		exit 1; \
	fi;
	@if [ ! -d ${LIGHTTPD_LOCATION} ]; then \
		echo "\"${LIGHTTPD_LOCATION}\" is not a directory"; \
		exit 1; \
	fi;
	@echo "copy mod_websocket files into ${LIGHTTPD_LOCATION}"
	cp src/mod_websocket*.{h,c} ${LIGHTTPD_LOCATION}/src
	@echo "done"

	@echo "patch the lighttpd sources"
	@(sh dopatch.sh ${LIGHTTPD_LOCATION})
	@echo "done"

	@echo "plz make lighty w/ mod_websocket like below"
	@echo
	@echo "$$ cd ${LIGHTTPD_LOCATION}"
	@echo "$$ ./autogen.sh"
	@echo "$$ ./configure --with-websocket[=ALL/RFC-6455/IETF-00]"
	@echo "$$ make"
	@echo
