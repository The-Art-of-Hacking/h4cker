# Podman vs Docker

- Docker uses a daemon, an ongoing program running in the background, to create images and run containers.
- Podman has a daemon-less architecture which means it can run containers under the user starting the container. 
- Docker has a client-server logic mediated by a daemon; Podman does not need the mediator.
- Podman allows for non-root privileges for containers.
- Rootless containers are considered safer than containers with root privileges

## Podman Rootless?

- Containers in Podman do not have root access by default, adding a natural barrier between root and rootless levels, improving security. 
- Still, Podman can run both root and rootless containers.

## What about Systemd?
- Without a daemon, Podman needs another tool to manage services and support running containers in the background. 
- Systemd creates control units for existing containers or to generate new ones. 
- Systemd can also be integrated with Podman allowing it to run containers with systemd enabled by default, without any modification.
- By using systemd, vendors can install, run, and manage their applications as containers since most are now exclusively packaged and delivered this way.

## Building images
- As a self-sufficient tool, Docker can build container images on its own. 
- Podman requires the assistance of another tool called Buildah, which expresses its specialized nature: it is made for running but not building containers on its own.



