# $Id$

FILES+=		pwdpolicies.tex pwdpolicies.bib
FILES+=		contents.tex aims.tex literature.tex acknowledgements.tex

USE_LATEXMK= 	yes
USE_BIBLATEX= 	yes

.PHONY: all
all: pwdpolicies.pdf

pwdpolicies.pdf: ${FILES}


### INCLUDES ###

INCLUDE_MAKEFILES=../makefiles
include ${INCLUDE_MAKEFILES}/tex.mk
