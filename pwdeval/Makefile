FILES+=		pwdeval.tex pwdeval.bib
FILES+=		contents.tex guessing.tex


.PHONY: all
all: pwdeval.pdf

pwdeval.pdf: ${FILES}


.PHONY: all container
all: container

DOCKER_USER_ID?=dbosk

container: Dockerfile
	docker build -t pwdeval .
	docker tag pwdeval ${DOCKER_USER_ID}/pwdeval


.PHONY: push
push:
	docker push ${DOCKER_USER_ID}/pwdeval


.PHONY: distclean
distclean:
	docker rm pwdeval
	docker rm ${DOCKER_USER_ID}/pwdeval


### INCLUDES ###

INCLUDE_MAKEFILES=../makefiles
include ${INCLUDE_MAKEFILES}/tex.mk
