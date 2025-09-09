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


Podman and Docker use similar container image formats, but there are some differences between them. Docker uses the Docker image format, typically with a `.tar` file extension, while Podman utilizes the Open Container Initiative (OCI) image format, which is typically in the form of a `.tar.gz` or `.tar` file.

Although Podman and Docker can both work with OCI-compliant images, there may be some subtle differences and specific features that are supported by one but not the other. However, in many cases, container images created for Docker can be used with Podman without any issues.

To convert a Docker image to a Podman image or vice versa, you can follow these general steps:

1. Save the Docker image:
   - For Docker: Use the `docker save` command to save the image as a `.tar` file.
   - For Podman: Podman can directly work with Docker images, so there is no need to convert if you are using Podman as it can directly pull and use Docker images.

2. Load the image:
   - For Docker: Use the `docker load` command to load the Docker image from the saved `.tar` file.
   - For Podman: Podman can use the Docker image directly without any conversion, so there is no need to load or convert the image.

It's worth noting that Podman provides a compatibility mode (`--cgroup-manager=cgroupfs`) that allows it to work with the traditional `cgroup` system used by Docker, which can be useful in certain scenarios.

While the image format itself is compatible, it's important to consider any specific features or dependencies that may be present in the original image, as there could be differences in behavior or functionality between Podman and Docker. Testing and validating the converted image in the target environment is recommended.

NOTE: When working with OCI-compliant images, such as those used by Docker and Podman, compatibility is generally high, but it's still recommended to test and validate the converted images to ensure expected behavior and functionality.

Here's a table comparing Podman and Docker:

| Feature                | Podman                                                         | Docker                                                          |
|------------------------|----------------------------------------------------------------|-----------------------------------------------------------------|
| Container Engine       | Uses a daemonless container engine                              | Uses a container engine with a client-server architecture        |
| Rootless Containers    | Supports running containers as non-root users                    | Requires root privileges for container operations               |
| Image Format           | Utilizes the OCI (Open Container Initiative) image format       | Uses its own Docker image format                                 |
| Image Compatibility    | Can directly use Docker images without conversion                | Requires Docker images to be converted for Podman compatibility |
| Container Orchestration| Supports Kubernetes-style orchestration through Podman Machine  | Provides built-in support for Docker Swarm and Kubernetes       |
| Networking             | Provides CNI (Container Networking Interface) compatibility     | Uses its own networking system based on libnetwork              |
| Daemon Management      | No separate daemon process needs to run in the background       | Requires a separate Docker daemon process to be running         |
| Integration with Tools | Works well with existing Docker tooling and commands             | Provides a rich ecosystem of tools and extensive community support |
| Security               | Emphasizes rootless and user namespace isolation for security    | Offers strong security features and isolation mechanisms        |
| Community Support      | Active community support and regular updates                     | Widely adopted with a large community and extensive resources   |
| Supported Platforms    | Runs on a variety of Linux distributions                         | Runs on a variety of Linux distributions, Windows, and macOS    |

Podman and Docker have their strengths and are suitable for different use cases. The choice between them depends on factors such as specific requirements, familiarity, and compatibility with existing infrastructure and workflows.
