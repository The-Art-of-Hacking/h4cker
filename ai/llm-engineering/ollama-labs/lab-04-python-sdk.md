# Lab 4: Python Programming with Ollama

## Objective
In this lab, you will learn how to use the official Ollama Python library to build Python applications that leverage local LLMs. You'll create scripts, handle responses, work with embeddings, and build practical applications.

## Prerequisites
- Completed Labs 1-3
- Python 3.8 or higher installed
- pip (Python package manager)
- Basic Python programming knowledge
- A code editor (VS Code, PyCharm, or any text editor)
- At least one Ollama model downloaded (e.g., `gemma3`)

## Estimated Time
75-90 minutes

## Part 1: Setup and Installation

### Step 1: Install the Ollama Python Library

```bash
pip install ollama
```

Or with uv:
```bash
uv add ollama
```

### Step 2: Verify Installation

Create a file named `test_ollama.py`:

```python
import ollama

# Check if ollama module is imported successfully
print("Ollama Python library version:", ollama.__version__)
```

Run it:
```bash
python test_ollama.py
```

### Step 3: Create a Project Directory

```bash
mkdir ollama-python-lab
cd ollama-python-lab
```

## Part 2: Basic Chat Interactions

### Step 1: Simple Chat

Create `simple_chat.py`:

```python
from ollama import chat
from ollama import ChatResponse

response: ChatResponse = chat(model='gemma3', messages=[
  {
    'role': 'user',
    'content': 'Why is the sky blue?',
  },
])

print(response['message']['content'])
# or access fields directly from the response object
print(response.message.content)
```

Run it:
```bash
python simple_chat.py
```

### Step 2: Chat with System Message

Create `chat_with_system.py`:

```python
from ollama import chat

response = chat(
    model='gemma3',
    messages=[
        {
            'role': 'system',
            'content': 'You are a helpful assistant that explains technical concepts to children.'
        },
        {
            'role': 'user',
            'content': 'What is a computer?'
        }
    ]
)

print(response.message.content)
```

### Step 3: Multi-Turn Conversation

Create `conversation.py`:

```python
from ollama import chat

messages = []

# First user message
messages.append({
    'role': 'user',
    'content': 'What is Python?'
})

response = chat(model='gemma3', messages=messages)
messages.append(response.message)

print("Assistant:", response.message.content)
print("\n" + "="*50 + "\n")

# Second user message
messages.append({
    'role': 'user',
    'content': 'What are its main advantages?'
})

response = chat(model='gemma3', messages=messages)
messages.append(response.message)

print("Assistant:", response.message.content)
```

## Part 3: Streaming Responses

### Step 1: Basic Streaming

Create `streaming_chat.py`:

```python
from ollama import chat

stream = chat(
    model='gemma3',
    messages=[{'role': 'user', 'content': 'Tell me a story about a robot.'}],
    stream=True,
)

print("Response: ", end='', flush=True)
for chunk in stream:
    print(chunk['message']['content'], end='', flush=True)
print()  # New line at the end
```

### Step 2: Streaming with Progress Indication

Create `streaming_with_progress.py`:

```python
from ollama import chat
import sys

stream = chat(
    model='gemma3',
    messages=[{'role': 'user', 'content': 'Explain machine learning in detail.'}],
    stream=True,
)

print("Generating response...\n")
full_response = ""

for chunk in stream:
    content = chunk['message']['content']
    full_response += content
    print(content, end='', flush=True)
    
print(f"\n\nTotal characters: {len(full_response)}")
```

## Part 4: Working with Options

### Step 1: Temperature Control

Create `temperature_comparison.py`:

```python
from ollama import chat

prompt = "Write a creative opening line for a science fiction story."

print("Low Temperature (0.2) - More focused:")
response_low = chat(
    model='gemma3',
    messages=[{'role': 'user', 'content': prompt}],
    options={'temperature': 0.2}
)
print(response_low.message.content)

print("\n" + "="*50 + "\n")

print("High Temperature (0.9) - More creative:")
response_high = chat(
    model='gemma3',
    messages=[{'role': 'user', 'content': prompt}],
    options={'temperature': 0.9}
)
print(response_high.message.content)
```

### Step 2: Controlling Output Length

Create `controlled_length.py`:

```python
from ollama import chat

response = chat(
    model='gemma3',
    messages=[{
        'role': 'user',
        'content': 'Write a long essay about artificial intelligence.'
    }],
    options={
        'num_predict': 100,  # Limit to 100 tokens
        'temperature': 0.7
    }
)

print(response.message.content)
```

## Part 5: Embeddings

### Step 1: Generate Embeddings

Create `generate_embeddings.py`:

```python
from ollama import embed

# Single embedding
response = embed(
    model='nomic-embed-text',
    input='The quick brown fox jumps over the lazy dog'
)

print(f"Embedding dimension: {len(response['embeddings'][0])}")
print(f"First 10 values: {response['embeddings'][0][:10]}")
```

### Step 2: Semantic Similarity

Create `semantic_similarity.py`:

```python
from ollama import embed
import numpy as np

def cosine_similarity(vec1, vec2):
    """Calculate cosine similarity between two vectors"""
    return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))

# Sentences to compare
sentences = [
    "The cat sits on the mat",
    "A feline rests on the carpet",
    "I love eating pizza",
]

# Generate embeddings
embeddings = []
for sentence in sentences:
    response = embed(model='nomic-embed-text', input=sentence)
    embeddings.append(response['embeddings'][0])

# Compare similarities
print("Similarity between sentences:")
print(f"Sentence 1 vs 2: {cosine_similarity(embeddings[0], embeddings[1]):.4f}")
print(f"Sentence 1 vs 3: {cosine_similarity(embeddings[0], embeddings[2]):.4f}")
print(f"Sentence 2 vs 3: {cosine_similarity(embeddings[1], embeddings[2]):.4f}")
```

Run it:
```bash
pip install numpy  # Install numpy first
python semantic_similarity.py
```

## Part 6: Practical Applications

### Step 1: Interactive Chatbot

Create `interactive_chatbot.py`:

```python
from ollama import chat

def chatbot():
    """Simple interactive chatbot"""
    messages = []
    
    print("Chatbot started! Type 'quit' to exit.")
    print("="*50)
    
    while True:
        user_input = input("\nYou: ")
        
        if user_input.lower() in ['quit', 'exit', 'bye']:
            print("Goodbye!")
            break
        
        messages.append({
            'role': 'user',
            'content': user_input
        })
        
        print("Assistant: ", end='', flush=True)
        
        stream = chat(model='gemma3', messages=messages, stream=True)
        assistant_message = ""
        
        for chunk in stream:
            content = chunk['message']['content']
            assistant_message += content
            print(content, end='', flush=True)
        
        print()  # New line
        
        messages.append({
            'role': 'assistant',
            'content': assistant_message
        })

if __name__ == "__main__":
    chatbot()
```

### Step 2: Document Summarizer

Create `document_summarizer.py`:

```python
from ollama import chat
import sys

def summarize_file(filename, summary_length='short'):
    """Summarize a text file"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return
    
    length_instruction = {
        'short': 'in one paragraph',
        'medium': 'in 2-3 paragraphs',
        'long': 'in detail with multiple paragraphs'
    }
    
    prompt = f"Summarize the following text {length_instruction[summary_length]}:\n\n{content}"
    
    print(f"Generating {summary_length} summary...\n")
    
    response = chat(
        model='gemma3',
        messages=[{'role': 'user', 'content': prompt}],
    )
    
    print("Summary:")
    print("="*50)
    print(response.message.content)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python document_summarizer.py <filename> [short|medium|long]")
        sys.exit(1)
    
    filename = sys.argv[1]
    summary_length = sys.argv[2] if len(sys.argv) > 2 else 'short'
    
    summarize_file(filename, summary_length)
```

Test it by creating a sample file:
```bash
echo "Artificial intelligence (AI) is transforming many industries..." > sample.txt
python document_summarizer.py sample.txt short
```

### Step 3: Code Explainer

Create `code_explainer.py`:

```python
from ollama import chat

def explain_code(code_snippet, language='python'):
    """Explain a code snippet"""
    
    prompt = f"""Explain this {language} code in detail:

```{language}
{code_snippet}
```

Provide:
1. What the code does
2. How it works line by line
3. Any potential improvements or issues
"""
    
    response = chat(
        model='gemma3',
        messages=[{
            'role': 'system',
            'content': 'You are an expert programming tutor.'
        }, {
            'role': 'user',
            'content': prompt
        }]
    )
    
    return response.message.content

# Example usage
sample_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""

explanation = explain_code(sample_code)
print(explanation)
```

## Part 7: Error Handling and Best Practices

### Step 1: Robust Error Handling

Create `error_handling.py`:

```python
from ollama import chat, ResponseError, RequestError
import sys

def safe_chat(model, prompt):
    """Chat with proper error handling"""
    try:
        response = chat(
            model=model,
            messages=[{'role': 'user', 'content': prompt}]
        )
        return response.message.content
    
    except ResponseError as e:
        print(f"Error from Ollama: {e}")
        return None
    
    except RequestError as e:
        print(f"Request error: {e}")
        print("Make sure Ollama is running (ollama serve)")
        return None
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# Test
result = safe_chat('gemma3', 'Hello!')
if result:
    print(result)
```

### Step 2: Response Validation

Create `response_validation.py`:

```python
from ollama import chat
import json

def get_structured_response(prompt, expected_keys):
    """Get a JSON response and validate its structure"""
    
    response = chat(
        model='gemma3',
        messages=[{'role': 'user', 'content': prompt}],
        format='json'
    )
    
    try:
        data = json.loads(response.message.content)
        
        # Validate expected keys
        missing_keys = [key for key in expected_keys if key not in data]
        if missing_keys:
            print(f"Warning: Missing keys: {missing_keys}")
        
        return data
    
    except json.JSONDecodeError:
        print("Error: Response is not valid JSON")
        return None

# Example
prompt = """Generate a person profile with name, age, and occupation. 
Respond in JSON format."""

result = get_structured_response(prompt, ['name', 'age', 'occupation'])
print(result)
```

## Exercises

### Exercise 1: Language Translator

Create a Python script that:
1. Takes text and target language as input
2. Translates the text using Ollama
3. Outputs the translation

```python
def translate(text, target_language):
    # Your code here
    pass
```

### Exercise 2: Sentiment Analyzer

Build a sentiment analyzer that:
1. Takes a text review as input
2. Analyzes sentiment (positive/negative/neutral)
3. Returns sentiment and confidence score in JSON format

### Exercise 3: Question-Answering System

Create a Q&A system that:
1. Reads a document/article
2. Accepts questions about the content
3. Provides answers based on the document

### Exercise 4: Batch Processor

Build a script that:
1. Reads multiple prompts from a CSV file
2. Processes them in batch
3. Saves responses to an output CSV file

### Exercise 5: Conversation Logger

Enhance the interactive chatbot to:
1. Save conversation history to a JSON file
2. Load previous conversations
3. Continue from where you left off

## Lab Questions

1. What is the difference between `chat()` and `generate()` in the Python SDK?
2. How do you enable streaming in the Python SDK?
3. What are the benefits of using the Python SDK over direct REST API calls?
4. How do you handle errors when the model doesn't exist?
5. What is the purpose of embeddings in semantic search?
6. How can you ensure reproducible outputs in Python?

## Advanced Challenges

### Challenge 1: Mini RAG System

Build a simple Retrieval-Augmented Generation system:
1. Load multiple documents
2. Create embeddings for each
3. Find relevant documents based on a query
4. Use relevant context to answer questions

### Challenge 2: Multi-Model Application

Create an application that:
1. Uses a vision model to describe images
2. Uses a text model to write stories based on descriptions
3. Compares outputs from different models

### Challenge 3: Smart Assistant

Build a smart assistant that can:
1. Maintain conversation context
2. Extract structured information from conversations
3. Perform different tasks based on user intent
4. Save and load conversation state

## Summary

In this lab, you learned how to:
- Install and use the Ollama Python library
- Create chat applications with streaming support
- Work with embeddings for semantic similarity
- Build practical applications (chatbot, summarizer, code explainer)
- Handle errors and validate responses
- Use advanced features like temperature control and structured outputs

## Next Steps

Continue to **Lab 5: Creating Custom Models with Modelfiles** to learn how to customize models for specific use cases.

