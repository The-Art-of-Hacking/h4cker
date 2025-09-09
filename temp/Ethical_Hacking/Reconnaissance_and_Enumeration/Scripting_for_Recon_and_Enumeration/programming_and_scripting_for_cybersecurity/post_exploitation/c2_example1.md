# Example of Creating a C2 Using Python
Let's create a Python script that sets up a listener to communicate with a remote device. The listener waits for a connection, then allows the user to send commands to the remote device. 
🤖 Checkout [this prompt in ChatGPT](https://chat.openai.com/share/a8399b03-9d33-444a-bce3-e7995d351316)

Here's a breakdown of the code:

1. **Importing Required Module**:
   ```python
   import socket
   ```
   The script imports the `socket` module, which provides a way for Python to interact with network sockets.

2. **Identifier Constant**:
   ```python
   IDENTIFIER = "<END_OF_COMMAND_RESULT>"
   ```
   This string serves as an identifier to determine the end of a command result.

3. **Main Script Execution**:
   The script uses an `if __name__ == "__main__":` block to ensure that the code inside it only runs if the script is executed directly (and not imported as a module).

4. **Setting Up the Socket**:
   ```python
   hacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   ```
   A new TCP socket (`SOCK_STREAM`) is created for IPv4 communication (`AF_INET`).

5. **Socket Address Configuration**:
   ```python
   IP = "10.6.6.88"
   Port = 1337
   socket_address = (IP, Port)
   ```
   The IP address and port for the listener are defined.

6. **Binding and Listening**:
   ```python
   hacker_socket.bind(socket_address)
   hacker_socket.listen(5)
   print("listening for incoming connection requests")
   ```
   The socket is bound to the specified IP address and port, and it starts listening for incoming connections with a backlog of 5.

7. **Accepting Connections**:
   ```python
   hacker_socket, client_address = hacker_socket.accept()
   print("connection established with ", client_address)
   ```
   The script waits for a connection. When one is established, it prints the client's address.

8. **Command Loop**:
   The main loop of the script lets the user input commands to send to the connected device:
   - If the command is "stop", the socket closes and the script ends.
   - If the command is empty, the loop continues without sending anything.
   - If the command starts with "cd", it sends the command and moves to the next iteration.
   - For other commands, it sends the command and waits for a response. The response is received in chunks and the loop continues until the `IDENTIFIER` is found.

9. **Exception Handling**:
   If any exception occurs during command execution or communication, the script prints "Exception occurred" and closes the socket.


