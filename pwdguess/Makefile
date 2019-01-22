# $Id$

FILES=		pwdguess.tex contents.tex aims.tex literature.tex pwdguess.bib
FILES+= 	unix-passwd.txt win-pwd.txt pwdstream.py sshforce.py

USE_LATEXMK= 	yes
USE_BIBLATEX= 	yes

.PHONY: all
all: pwdguess.pdf

pwdguess.pdf: ${FILES}


### INCLUDES ###

INCLUDE_MAKEFILES=../makefiles
include ${INCLUDE_MAKEFILES}/tex.mk
