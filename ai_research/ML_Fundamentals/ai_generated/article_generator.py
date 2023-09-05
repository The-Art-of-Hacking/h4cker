'''
A simple test to use AI (OpenAI API) to generate an article based on a list of ideas.
You can do this a lot better using LangChain. However, this is a simple example to demonstrate how to use the OpenAI API.
Author: Omar Santos, os@cisco.com, @santosomar
'''

# Import the required libraries
# Install all the required libraries using pip install openai python-dotenv 
from dotenv import load_dotenv
import openai
import os
import sys

# Load the .env file
load_dotenv()

# Get the API key from the environment variable
openai.api_key = os.getenv('OPENAI_API_KEY')

# Read the ideas from a file (ideas.txt)
with open('ideas.txt', 'r') as file:
    lines = file.readlines()

# Read lines one by one
for line in lines:
    # Create a filename
    filename = line.strip().replace(' ', '_') + '.md'
    idea = line.strip()

    # Create a path to save the files in a specific directory
    filepath = os.path.join('data', filename)

    # Prepare the prompt
    prompt = [{"role": "user", "content": f"Create an article about  {idea}."}]
    # Generate the AI response using the GPT-3.5 model (16k)
    # https://beta.openai.com/docs/api-reference/create-completion
    response = openai.ChatCompletion.create(
      model="gpt-3.5-turbo-16k",
      messages=prompt,
      max_tokens=15000
    )

    # print the AI response
    final_response = response.choices[0].message.content

    print(final_response)
   
    # Create a new markdown file and write the article
    with open(filepath, 'w') as md_file:
        md_file.write(final_response)
