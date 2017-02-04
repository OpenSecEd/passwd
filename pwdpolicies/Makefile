# $Id$

FILES+=		pwdpolicies.tex aims.tex literature.tex pwdpolicies.bib
FILES+=		contents.tex

USE_LATEXMK= 	yes
USE_BIBLATEX= 	yes

.PHONY: all
all: pwdpolicies.pdf

pwdpolicies.pdf: ${FILES} llncs


### INCLUDES ###

INCLUDE_MAKEFILES=../makefiles
include ${INCLUDE_MAKEFILES}/tex.mk
