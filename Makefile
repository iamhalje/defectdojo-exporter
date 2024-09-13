# DOCKER TASKS

DOCKER_IMAGE_NAME := exporter
DOCKER_IMAGE_TAG := defectdojo
DOCKER_CONTAINER_NAME := defectdojo-exporter

.PHONY: all build run extract clean

all: build run extract clean

build:
	docker build -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG) .

run:
	docker run --name $(DOCKER_CONTAINER_NAME) $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)

extract:
	docker cp $(DOCKER_CONTAINER_NAME):/usr/local/bin/defectdojo-exporter ./defectdojo-exporter

clean:
	docker stop $(DOCKER_CONTAINER_NAME) || true
	docker rm $(DOCKER_CONTAINER_NAME) || true
