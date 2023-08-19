'''
A simple test to interact with the OpenAI API
and analyze logs from applications, firewalls, operating systems, and more.
Author: Omar Santos, @santosomar
'''

# Import the required libraries
# pip3 install openai python-dotenv  
# Use the line above if you need to install the libraries
from dotenv import load_dotenv
import openai
import os

# Load the .env file
load_dotenv()

# Get the API key from the environment variable
openai.api_key = os.getenv('OPENAI_API_KEY')

# Read the diff from a file
with open('logs.txt', 'r') as file:
    log_file = file.read()

# Prepare the prompt
prompt = [{"role": "user", "content": f"Explain the following logs:\n\n{log_file} . Explain if there is any malicious activity in the logs."}]

# Generate the AI chat completion via the OpenAI API
# I am only using GTP 3.5 Turbo for this example.
response = openai.ChatCompletion.create(
  model="gpt-3.5-turbo-16k",
  messages=prompt,
  max_tokens=10000
)

# print the response from the OpenAI API
print(response.choices[0].message.content)


