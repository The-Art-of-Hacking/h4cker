# Linux metacharacters

1. `;` : Separates commands.
    ```
    command1 ; command2 # Run command1, then run command2 regardless of whether command1 succeeded.
    ```

2. `&` : Background execution.
    ```
    command & # Runs "command" in the background.
    ```

3. `&&` : AND operator.
    ```
    command1 && command2 # Run command1, then run command2 only if command1 succeeded.
    ```

4. `||` : OR operator.
    ```
    command1 || command2 # Run command1, then run command2 only if command1 failed.
    ```

5. `|` : Pipe operator.
    ```
    command1 | command2 # Output of command1 is passed as input to command2.
    ```

6. `()` : Command group.
    ```
    (command1; command2) # Group commands into a subshell.
    ```

7. `{}` : Command block.
    ```
    { command1; command2; } # Group commands in the current shell.
    ```

8. `$()` : Command substitution.
    ```
    echo $(command) # Runs "command" and substitutes its output in place.
    ```

9. ` `` ` (Backticks): Another way of command substitution.
    ```
    echo `command` # Same as above, but this syntax can be harder to spot.
    ```

10. `>` : Output redirection.
    ```
    command > file # Redirect the output of command to a file, overwriting the file.
    ```

11. `>>` : Append output.
    ```
    command >> file # Append the output of command to a file.
    ```

12. `<` : Input redirection.
    ```
    command < file # Use "file" as input for command.
    ```

13. `2>` : Error redirection.
    ```
    command 2> file # Redirect the error output of command to a file, overwriting the file.
    ```

14. `2>>` : Append error output.
    ```
    command 2>> file # Append the error output of command to a file.
    ```

15. `&>` : Redirect all output (stdout and stderr).
    ```
    command &> file # Redirect all output of command to a file, overwriting the file.
    ```

16. `*` : Wildcard.
    ```
    ls *.txt # List all .txt files.
    ```

17. `?` : Single character wildcard.
    ```
    ls ?.txt # List all .txt files with a single character name.
    ```

18. `[]` : Character class.
    ```
    ls [ab]*.txt # List all .txt files starting with 'a' or 'b'.
    ```

19. `!` : Negation.
    ```
    command1; ! command1 # Execute command1, then execute command1 again only if the first execution failed.
    ```

20. `#` : Comment.
    ```
    # This is a comment in Bash.
    ```
 
21. `\$` : Escape character.  
    ```
    echo \$HOME # prints $HOME, not the value of the variable.
    ```

22. `\"` : Escape character for quotes.
    ```
    echo "This is a \"quote\"" # prints This is a "quote".
    ```
 
Be careful, especially when using redirections, as they can overwrite your files without warning if you're not careful.
