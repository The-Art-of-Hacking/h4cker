# SECCOMP
To use seccomp (Secure Computing Mode) with Docker, you can follow these steps:

1. Enable seccomp in the Docker daemon:
   - Open the Docker daemon configuration file, typically located at `/etc/docker/daemon.json`.
   - Add the following configuration to enable seccomp:
     ```json
     {
       "seccomp-profiles": [
         {
           "name": "default",
           "path": "/path/to/seccomp/profile.json"
         }
       ]
     }
     ```
     Replace `/path/to/seccomp/profile.json` with the actual path to your seccomp profile JSON file.
   - Save the configuration file and restart the Docker daemon to apply the changes.

2. Create a seccomp profile JSON file:
   - Create a JSON file that defines the seccomp profile for your Docker containers. This file specifies the system calls that are allowed or denied within the container.
   - You can create your own custom seccomp profile or use an existing profile as a starting point. There are various sources available for seccomp profiles, such as the Docker seccomp repository on GitHub, which provides pre-defined profiles for common use cases.
   - Define the desired system calls and their corresponding actions (allow or deny) in the JSON file.
   - Save the seccomp profile JSON file.

3. Apply the seccomp profile to a container:
   - When running a container, use the `--security-opt` flag to apply the seccomp profile. For example:
     ```
     docker run --security-opt seccomp=/path/to/seccomp/profile.json <image>
     ```
     Replace `/path/to/seccomp/profile.json` with the actual path to your seccomp profile JSON file, and `<image>` with the name of the Docker image you want to run.

By following these steps, you can enable and use seccomp with Docker to restrict the system calls available within your containers. This helps to enhance security by limiting the container's capabilities and reducing the potential attack surface.

`seccomp` is a powerful security feature that should be used carefully. Ensure that the seccomp profile allows the necessary system calls for your application to function correctly. Monitor and test your containers to verify that the applied seccomp profile does not cause any issues or unintended consequences.
