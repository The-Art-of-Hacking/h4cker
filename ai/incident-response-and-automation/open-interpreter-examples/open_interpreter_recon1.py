'''
This script is a basic example of how to use the Open Interpreter library to perform passive reconnaissance on a target domain.
'''

# Import the Open Interpreter library
# To install the library, run: pip install open-interpreter
from interpreter import interpreter

# Set the LLM model to use
interpreter.llm.model = "gpt-4o-mini"

# Set the system message
# interpreter.system_message += """
# Run shell commands with -y so the user doesn't have to confirm them.
# """
# print(interpreter.system_message)

# Perform passive reconnaissance on the target domain
interpreter.chat("Use Amass to perform passive reconnaissance on secretcorp.org. Analyze the output. Save the output and analysis to a file called secretcorp.md.")

# Start an interactive chat
interpreter.chat()
