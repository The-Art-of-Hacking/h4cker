# User Management Basic Commands
There are several commands that are crucial when managing users in Linux. Here are some of the most important ones:

1. `useradd`: This command is used to create a new user. For example: `useradd username`

2. `usermod`: This command modifies the properties of an existing user. For example, to add a user to a group: `usermod -aG groupname username`

3. `userdel`: This command deletes a user. For example: `userdel username`. Be careful with this command, it should be used with caution.

4. `passwd`: This command is used to change the user's password. For example, to change the password for a user: `passwd username`

5. `su`: This command is used to switch the current user to another user. For example, to switch to a user named "username", you would type: `su username`

6. `sudo`: This command is used to run commands with administrative privileges. For example: `sudo command`. It's equivalent to saying "run this command as the superuser".

7. `chown`: This command is used to change the owner of a file or directory. For example: `chown username filename`

8. `chgrp`: This command is used to change the group of a file or directory. For example: `chgrp groupname filename`

9. `groups`: This command is used to display the groups a user is a part of. For example: `groups username`

10. `id`: This command is used to display the user ID and group ID of a user. For example: `id username`

11. `whoami`: This command is used to display the current logged in user. Just type: `whoami`

12. `adduser`: This command is used to add a user (more user friendly than `useradd`). For example: `adduser username`

13. `addgroup`: This command is used to add a group. For example: `addgroup groupname`

14. `deluser`: This command is used to remove a user. For example: `deluser username`

15. `delgroup`: This command is used to remove a group. For example: `delgroup groupname`

Remember, the manual (`man`) pages are your best friend when learning about commands in Linux. You can access the man page for any command by typing `man` followed by the command name. For example, `man useradd` will show you the man page for the `useradd` command.
