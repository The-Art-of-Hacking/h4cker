run:
	docker run -i -d -p 8080:8080 node-distroless 

build-naive:
	docker build \
	-f $(CURDIR)/Dockerfile.naive \
	-t node-naive \
	.

build-non-root:
	docker build \
	-f $(CURDIR)/Dockerfile.non-root \
	-t node-non-root \
	.

build-distroless:
	docker build \
	-f $(CURDIR)/Dockerfile.distroless \
	-t node-distroless \
	.