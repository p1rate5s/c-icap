

# lib_LTLIBRARIES=sys_logger.la perl_handler.la

pkglib_LTLIBRARIES= sys_logger.la dnsbl_tables.la
if USEPERL
pkglib_LTLIBRARIES += perl_handler.la
endif

if USEBDB
pkglib_LTLIBRARIES += bdb_tables.la
endif

if USELDAP
pkglib_LTLIBRARIES += ldap_module.la
endif

INCLUDES = -I$(top_srcdir)

sys_logger_la_LIBADD = @MODULES_LIBADD@
sys_logger_la_CFLAGS=  @MODULES_CFLAGS@ -I../include/
sys_logger_la_LDFLAGS= -module -avoid-version
sys_logger_la_SOURCES = sys_logger.c

dnsbl_tables_la_LIBADD = @MODULES_LIBADD@
dnsbl_tables_la_CFLAGS=  @MODULES_CFLAGS@ -I../include/
dnsbl_tables_la_LDFLAGS= -module -avoid-version
dnsbl_tables_la_SOURCES = dnsbl_tables.c

perl_handler_la_LIBADD = @MODULES_LIBADD@ @perllib@  -L@perlcore@ -lperl
perl_handler_la_CFLAGS=  @MODULES_CFLAGS@ -I../include/ @perlccflags@ -I@perlcore@
perl_handler_la_LDFLAGS= -module -avoid-version @perlldflags@
perl_handler_la_SOURCES = perl_handler.c


bdb_tables_la_LIBADD = @MODULES_LIBADD@ @BDB_ADD_LDADD@
bdb_tables_la_CFLAGS=  @MODULES_CFLAGS@ -I../include/  @BDB_ADD_FLAG@
bdb_tables_la_LDFLAGS= -module -avoid-version
bdb_tables_la_SOURCES = bdb_tables.c

ldap_module_la_LIBADD = @MODULES_LIBADD@ @LDAP_ADD_LDADD@ $(top_srcdir)/libicapapi.la
ldap_module_la_CFLAGS=  @MODULES_CFLAGS@ -I../include/ @LDAP_ADD_FLAG@
ldap_module_la_LDFLAGS= -module -avoid-version
ldap_module_la_SOURCES = ldap_module.c



