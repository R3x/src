#	$NetBSD: Makefile,v 1.3 2017/01/11 12:02:32 joerg Exp $

LIB=	clangToolingCore

.include <bsd.init.mk>

.PATH: ${CLANG_SRCDIR}/lib/Tooling/Core

SRCS+=	Diagnostic.cpp \
	Lookup.cpp \
	QualTypeNames.cpp \
	Replacement.cpp

.if defined(HOSTLIB)
.include <bsd.hostlib.mk>
.else
.include <bsd.lib.mk>
.endif
