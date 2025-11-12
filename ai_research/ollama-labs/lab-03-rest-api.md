# Lab 3: Using the Ollama REST API

## Objective
In this lab, you will learn how to interact with Ollama using its REST API. You'll make HTTP requests using curl and learn how to integrate Ollama into applications through API calls. This is essential for building applications that use local LLMs.

## Prerequisites
- Completed Lab 1 and Lab 2
- Ollama installed and running
- At least one model downloaded (e.g., `gemma3`)
- Basic understanding of HTTP and REST APIs
- `curl` installed (usually pre-installed on macOS/Linux)
- Basic understanding of JSON

## Estimated Time
60-75 minutes

## Part 1: Understanding the API

### Step 1: Verify Ollama Service is Running

Ollama runs a local API server on port 11434 by default. Verify it's running:

```bash
ollama serve
```

(If already running, you'll see a message indicating the server is already active)

### Step 2: Check API Version

```bash
curl http://localhost:11434/api/version
```

Expected response:
```json
{
  "version": "0.12.10"
}
```


### Step 3: List Available Models via API

```bash
curl http://localhost:11434/api/tags
```

This returns a JSON list of all models installed locally.

## Part 2: Generate API - Text Completion

The `/api/generate` endpoint is used for text completion (non-chat format).

### Step 1: Basic Generation (Streaming)

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "Why is the sky blue?"
}'
```

**Observation**: The response streams back in multiple JSON objects, each containing a portion of the response.

### Step 2: Non-Streaming Generation

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "Why is the sky blue?",
  "stream": false
}'
```

**Observation**: The entire response comes back in a single JSON object.

### Step 3: Understanding the Response

The response contains:
- `response`: The generated text
- `done`: Whether generation is complete
- `total_duration`: Time taken (in nanoseconds)
- `load_duration`: Time to load the model
- `prompt_eval_count`: Number of tokens in the prompt
- `eval_count`: Number of tokens generated

### Step 4: Generation with Options

Set temperature and other parameters:

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "Write a creative story about a robot:",
  "stream": false,
  "options": {
    "temperature": 0.9,
    "num_predict": 100
  }
}'
```

## Part 3: Chat API - Conversational Format

The `/api/chat` endpoint provides a conversational interface with message history.

### Step 1: Simple Chat Request

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "gemma3",
  "messages": [
    {
      "role": "user",
      "content": "What is machine learning?"
    }
  ],
  "stream": false
}'
```

### Step 2: Chat with System Message

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "gemma3",
  "messages": [
    {
      "role": "system",
      "content": "You are a helpful AI assistant that explains concepts in simple terms suitable for beginners."
    },
    {
      "role": "user",
      "content": "What is quantum computing?"
    }
  ],
  "stream": false
}'
```

### Step 3: Multi-Turn Conversation

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "gemma3",
  "messages": [
    {
      "role": "user",
      "content": "What is Python?"
    },
    {
      "role": "assistant",
      "content": "Python is a high-level programming language known for its simplicity and readability."
    },
    {
      "role": "user",
      "content": "What are its main uses?"
    }
  ],
  "stream": false
}'
```

## Part 4: JSON Mode and Structured Outputs

### Step 1: JSON Mode

Request output in JSON format:

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "List three programming languages and their main uses. Respond using JSON with the format: {\"languages\": [{\"name\": \"...\", \"use\": \"...\"}]}",
  "format": "json",
  "stream": false
}'
```

### Step 2: Structured Outputs with Schema

Enforce a specific JSON schema:

```bash
curl -X POST http://localhost:11434/api/generate -H "Content-Type: application/json" -d '{
  "model": "gemma3",
  "prompt": "Generate information about a person named Alice who is 30 years old and works as an engineer.",
  "stream": false,
  "format": {
    "type": "object",
    "properties": {
      "name": {
        "type": "string"
      },
      "age": {
        "type": "integer"
      },
      "occupation": {
        "type": "string"
      },
      "employed": {
        "type": "boolean"
      }
    },
    "required": ["name", "age", "occupation", "employed"]
  }
}'
```

## Part 5: Embeddings API

### Step 1: Generate Single Embedding

```bash
curl http://localhost:11434/api/embed -d '{
  "model": "nomic-embed-text",
  "input": "Why is the sky blue?"
}'
```

### Step 2: Generate Multiple Embeddings

```bash
curl http://localhost:11434/api/embed -d '{
  "model": "nomic-embed-text",
  "input": [
    "The sky is blue",
    "The ocean is vast",
    "Mountains are tall"
  ]
}'
```

## Part 6: Model Management via API

### Step 1: Show Model Information

```bash
curl http://localhost:11434/api/show -d '{
  "model": "gemma3"
}'
```

### Step 2: Pull a Model

```bash
curl http://localhost:11434/api/pull -d '{
  "model": "llama3.2:latest",
  "stream": false
}'
```

### Step 3: Copy a Model

```bash
curl http://localhost:11434/api/copy -d '{
  "source": "gemma3",
  "destination": "gemma3-test"
}'
```

### Step 4: Delete a Model

```bash
curl -X DELETE http://localhost:11434/api/delete -d '{
  "model": "gemma3-test"
}'
```

### Step 5: List Running Models

```bash
curl http://localhost:11434/api/ps
```

## Part 7: Advanced API Features

### Step 1: Reproducible Outputs with Seed

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "Generate a random number between 1 and 100",
  "stream": false,
  "options": {
    "seed": 42,
    "temperature": 0
  }
}'
```

Run this multiple times - the output should be identical.

### Step 2: Context Window Management

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "Write a long essay about artificial intelligence",
  "stream": false,
  "options": {
    "num_ctx": 2048
  }
}'
```

### Step 3: Model Keep-Alive Control

Load a model and keep it in memory for 10 minutes:

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "",
  "keep_alive": "10m"
}'
```

Unload a model immediately:

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "gemma3",
  "prompt": "",
  "keep_alive": 0
}'
```

## Exercises

### Exercise 1: Build a Simple Chat Script

Create a bash script (`chat.sh`) that:
1. Takes a user question as a command-line argument
2. Sends it to the Ollama API
3. Extracts and prints only the response content

Example:
```bash
#!/bin/bash
QUESTION="$1"
curl -s http://localhost:11434/api/chat -d "{
  \"model\": \"gemma3\",
  \"messages\": [{\"role\": \"user\", \"content\": \"$QUESTION\"}],
  \"stream\": false
}" | jq -r '.message.content'
```

Usage: `./chat.sh "What is AI?"`

### Exercise 2: JSON Data Extraction

Use the API to extract structured data from unstructured text:

1. Create a prompt that asks the model to extract names, dates, and locations from a text
2. Use JSON mode to get structured output
3. Test with different input texts

### Exercise 3: Embedding-Based Similarity

1. Generate embeddings for 5 different sentences
2. Save them to files
3. Calculate which sentences are most similar (you can use Python/another language for the calculation)

Example sentences:
- "The cat sleeps on the couch"
- "A feline rests on the sofa"
- "I love to eat pizza"
- "Dogs are loyal animals"
- "The kitten naps on the furniture"

### Exercise 4: Performance Benchmarking

Create a script that:
1. Sends the same prompt to the API 10 times
2. Records the `total_duration` from each response
3. Calculates average, min, and max response times

### Exercise 5: Multi-Model Comparison

1. Send the same prompt to 3 different models
2. Compare:
   - Response quality
   - Response time
   - Token usage
3. Document your findings

## Lab Questions

1. What is the difference between `/api/generate` and `/api/chat` endpoints?
2. What does the `stream` parameter control?
3. How do you ensure reproducible outputs from the API?
4. What is the purpose of the `format` parameter in JSON mode?
5. How can you control how long a model stays in memory?
6. What information does the `eval_count` field provide?
7. How do embeddings differ from text generation?

## Advanced Challenges

### Challenge 1: Build a RAG System (Retrieval-Augmented Generation)

Create a simple RAG system:
1. Take a document and split it into chunks
2. Generate embeddings for each chunk
3. When a user asks a question:
   - Generate an embedding for the question
   - Find the most relevant chunk (closest embedding)
   - Use that chunk as context in a generation request

### Challenge 2: Create a Conversational API Wrapper

Build a script/application that:
1. Maintains conversation history
2. Sends multi-turn conversations to the API
3. Saves conversation history to a file
4. Allows loading previous conversations

### Challenge 3: API Response Parser

Create a tool that:
1. Makes API calls
2. Parses the streaming responses
3. Displays a real-time progress indicator
4. Saves the complete response to a file

## Troubleshooting

### Issue: Connection refused
- **Solution**: Ensure `ollama serve` is running

### Issue: Model not found
- **Solution**: Pull the model first using the CLI or API

### Issue: JSON parsing errors
- **Solution**: Ensure your JSON is properly formatted; use tools like `jq` to validate

### Issue: Slow responses
- **Solution**: Use smaller models or check system resources (RAM, CPU)

## Summary

In this lab, you learned how to:
- Make HTTP requests to the Ollama REST API
- Use both generate and chat endpoints
- Work with JSON mode and structured outputs
- Generate and use embeddings
- Manage models through the API
- Control model parameters and behavior
- Build scripts that integrate with Ollama

## Next Steps

Continue to **Lab 4: Python Programming with Ollama** to learn how to use the official Python SDK for more sophisticated applications.

