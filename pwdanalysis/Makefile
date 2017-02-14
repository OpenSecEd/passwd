# $Id$

CATEGORY=	security/compendii
DOCUMENTS=	pwdanalysis.pdf
FILES=		pwdanalysis.tex literature.bib

PACKAGE=		pwdanalysis-src
PACKAGE_FILES=	${FILES}

PUB_FILES=	${PACKAGE}.tar.gz ${DOCUMENTS}

USE_LATEXMK= 	true
USE_BIBLATEX= 	true

pwdanalysis.pdf: ${FILES}

#export no
literature.bib: ../../infosak.bib
	${CP} $^ $@

clean:
	${RM} literature.bib
#endexport	

miun.depend.mk:
	wget http://ver.miun.se/build/$@

include miun.depend.mk
include miun.course.mk
include miun.package.mk
