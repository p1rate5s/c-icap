SUBDIRS = . html

pkglib_LTLIBRARIES=srv_clamav.la
INCLUDES = -I$(top_srcdir)

srv_clamav_la_LIBADD = @MODULES_LIBADD@ @clamavlib@ -lclamav
srv_clamav_la_CFLAGS=  -I../../include/ @clamavinc@
srv_clamav_la_LDFLAGS=  -module -avoid-version
srv_clamav_la_SOURCES = srv_clamav.c srv_clamav_vir.c htmlTemplate.c

EXTRA_DIST = srv_clamav.h 
