.PHONY: all up down docker

repo_arg=
ifdef REPO
repo_arg=--build-arg REPO=$(REPO)
endif

branch_arg=
ifdef BRANCH
branch_arg=--build-arg BRANCH=$(BRANCH)
endif

nocache_arg=
ifdef NOCACHE
nocache_arg=--no-cache
endif

all: docker up

up:
	terraform apply
	ansible-playbook playbook-testnet.yml

down:
	terraform destroy -force

docker: docker-push-geth docker-push-mkkeystore docker-push-empty docker-push-raiden

aws-ecr-login:
	bash -c 'eval $$(aws ecr get-login --no-include-email) ;'

raiden-mk-appimage: ../../dist/raiden--x86_64.AppImage

../../dist/raiden--x86_64.AppImage:
	make -C ../../ bundle

docker-mk-geth:
	docker build -t brainbot/geth-testnet $(nocache_arg) files/dockerfiles/geth-testnet

docker-mk-mkkeystore:
	docker build -t brainbot/mkkeystore $(nocache_arg) files/dockerfiles/mkkeystore

docker-mk-empty:
	docker build -t brainbot/empty $(nocache_arg) files/dockerfiles/empty

docker-mk-raiden:
	# TODO: switch back to use AppImage
	docker build -t brainbot/raiden $(nocache_arg) $(repo_arg) $(branch_arg) files/dockerfiles/raiden

docker-push-geth: docker-mk-geth aws-ecr-login
	docker tag brainbot/geth-testnet 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/geth-testnet
	docker push 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/geth-testnet

docker-push-mkkeystore: docker-mk-mkkeystore aws-ecr-login
	docker tag brainbot/mkkeystore 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/mkkeystore
	docker push 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/mkkeystore

docker-push-empty: docker-mk-empty aws-ecr-login
	docker tag brainbot/empty 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/empty
	docker push 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/empty

docker-push-raiden: docker-mk-raiden aws-ecr-login
	docker tag brainbot/raiden 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/raiden
	docker push 147258760518.dkr.ecr.us-east-1.amazonaws.com/brainbot/raiden
