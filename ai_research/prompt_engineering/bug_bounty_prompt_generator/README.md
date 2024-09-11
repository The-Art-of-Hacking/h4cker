# AI Prompt Generator for Bug Bounty Vulnerabilities

This script generates AI-powered prompts for different vulnerabilities using OpenAI's GPT model. It's designed to assist ethical hackers and bug bounty hunters in creating detailed and specific prompts for different types of vulnerabilities.

## Features

- Reads a list of vulnerabilities from a file
- Generates AI-powered prompts for each vulnerability
- Saves each generated prompt to a separate file
- Uses OpenAI's GPT model via LangChain
- Implements a custom processing chain for prompt generation

## Prerequisites

- Python 3.6+
- OpenAI API key (set in .env file)
- Required Python packages (see [requirements.txt](requirements.txt))

## Setup

1. Clone this repository
2. Install required packages:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file in the project root and add your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```
4. Create a `top_vulns.txt` file in the project root, listing one vulnerability per line

## Usage

1. Ensure your `top_vulns.txt` file is populated with the vulnerabilities you want to generate prompts for
2. Run the script:
   ```
   python ai_prompt_maker.py
   ```
3. The script will process each vulnerability and generate a prompt
4. Generated prompts will be saved in the `prompts/` directory, with filenames based on the vulnerability names

## Output

- Console output will show each vulnerability being processed, the generated prompt, and the file where it was saved
- Generated prompts will be saved as text files in the `prompts/` directory
- Each prompt file will include a word count and the uppercase version of the prompt

## Customization

You can modify the system prompt in the script to adjust the style or focus of the generated prompts. Look for the `prompt_template` variable in the script.

