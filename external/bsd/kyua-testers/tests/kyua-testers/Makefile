# $NetBSD: Makefile,v 1.3 2016/08/26 23:55:04 dholland Exp $

.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/kyua-testers

SRCDIR=		${NETBSDSRCDIR}/external/bsd/kyua-testers/dist
.PATH:		${SRCDIR}

CPPFLAGS+=	-DHAVE_CONFIG_H
CPPFLAGS+=	-DTESTERSDIR=\"/usr/libexec\"
CPPFLAGS+=	-I${.CURDIR}/../../lib/libtester
CPPFLAGS+=	-I${SRCDIR}

ATFTESTER_LIBDIR!=	cd ${.CURDIR}/../../lib/libatf_tester; ${PRINTOBJDIR}
TESTER_LIBDIR!=		cd ${.CURDIR}/../../lib/libtester; ${PRINTOBJDIR}
LDADD+=		${ATFTESTER_LIBDIR}/libatf_tester.a
DPADD+=		${ATFTESTER_LIBDIR}/libatf_tester.a
LDADD+=		${TESTER_LIBDIR}/libtester.a
DPADD+=		${TESTER_LIBDIR}/libtester.a

TESTS_C=	atf_list_test
TESTS_C+=	atf_result_test
TESTS_C+=	atf_inttest
TESTS_C+=	cli_test
TESTS_C+=	env_test
TESTS_C+=	error_test
TESTS_C+=	fs_test
TESTS_C+=	plain_inttest
TESTS_C+=	result_test
TESTS_C+=	run_test
TESTS_C+=	stacktrace_test
TESTS_C+=	text_test

PROGS=				atf_helpers
BINDIR.atf_helpers=		${TESTSDIR}
MAN.atf_helpers=		# empty
LDADD.atf_helpers=		-latf-c++ -latf-c
DPADD.atf_helpers=		${LIBATF_CXX} ${LIBATF_C}
PROGS+=				plain_helpers
BINDIR.plain_helpers=		${TESTSDIR}
MAN.plain_helpers=		# empty
PROGS+=				stacktrace_helper
BINDIR.stacktrace_helper=	${TESTSDIR}
MAN.stacktrace_helper=		# empty

.include <bsd.test.mk>
