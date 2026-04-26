__author__ = "Omar Santos"
__version__ = "0.1.0"
__license__ = "MIT"
__description__ = "This script generates AI-powered prompts for various vulnerabilities in a web application. This could be used to help with bug bounty hunting and ethical hacking. It demonstrates the use of LangChain, OpenAI, and AI."

# Importing the required libraries
import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnableLambda

# Loading environment variables from .env
load_dotenv()

# Creating an instance of the ChatOpenAI model with the model name
model = ChatOpenAI(model="gpt-4o-mini")

# Defining the prompt templates
prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", "You are an expert Prompt Writer for Large Language Models and an expert in the subject of ethical hacking and bug bounty hunting. Start the prompt by stating that it is an expert in the subject. Be specific, descriptive and as detailed as possible about the desired outcome. You will help an ethical hacker to perform reconnaissance on a specific target for that given vulnerability and provide examples of exploits and how to exploit them."),
        ("human", "Create a prompt to help with {vulnerability}."),
    ]
)

# Defining additional processing steps using RunnableLambda
uppercase_output = RunnableLambda(lambda x: x.upper())
count_words = RunnableLambda(lambda x: f"Word count: {len(x.split())}\n{x}")

# Creating the combined chain using LangChain Expression Language (LCEL)
chain = prompt_template | model | StrOutputParser() | uppercase_output | count_words

# Creating the 'prompts' directory if it doesn't exist
os.makedirs("prompts", exist_ok=True)

# Reading vulnerabilities from the top_vulns.txt file
with open("top_vulns.txt", "r") as file:
    vulnerabilities = [line.strip() for line in file if line.strip()]

# Processing each vulnerability
for vulnerability in vulnerabilities:
    print(f"\nProcessing vulnerability: {vulnerability}")
    result = chain.invoke({"vulnerability": vulnerability})
    print(result)
    
    # Saving the result to a file
    filename = f"prompts/{vulnerability.replace(' ', '_').lower()}_prompt.txt"
    with open(filename, "w") as output_file:
        output_file.write(result)
    
    print(f"Saved prompt to: {filename}")
    print("-" * 80)  # Separator between results