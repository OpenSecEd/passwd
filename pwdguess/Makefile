# $Id$

FILES=		pwdguess.tex aims.tex literature.tex pwdguess.bib
FILES+= 	unix-passwd.txt win-pwd.txt pwdstream.py sshforce.py

USE_LATEXMK= 	yes
USE_BIBLATEX= 	yes

pwdguess.pdf: ${FILES} llncs


### INCLUDES ###

INCLUDE_MAKEFILES=../makefiles
include ${INCLUDE_MAKEFILES}/tex.mk
