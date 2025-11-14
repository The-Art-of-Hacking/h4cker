# Lab 2: Working with the CLI - Advanced Command-Line Operations

## Objective
In this lab, you will explore advanced CLI features of Ollama, including model management, configuration, embeddings generation, and working with different model variants. You'll gain proficiency in using Ollama from the command line for various tasks.

## Prerequisites
- Completed Lab 1 (Ollama installed and working)
- Basic understanding of command-line operations
- At least one model already downloaded (e.g., `gemma3`)

## Estimated Time
45-60 minutes

## Part 1: Model Discovery and Information

### Step 1: Explore Available Models

1. Visit the Ollama library in your browser: [https://ollama.com/library](https://ollama.com/library)
2. Browse different model families (Llama, Mistral, Gemma, etc.)
3. Note the different size variants (3B, 7B, 13B, etc.)

### Step 2: Understanding Model Tags

Models in Ollama follow the format: `model:tag`

Common tags:
- `latest` - The default version (used if no tag is specified)
- `3b`, `7b`, `13b` - Model size (billions of parameters)
- `q4_0`, `q4_K_M`, `q8_0` - Quantization levels (affects quality and size)

Example:
```bash
ollama pull llama3.2:3b
```

### Step 3: View Detailed Model Information

```bash
ollama show gemma3
```

Look at the output to understand:
- Model architecture
- Parameter count
- Quantization level
- System prompt template

View the Modelfile:
```bash
ollama show --modelfile gemma3
```

## Part 2: Working with Embeddings

Embeddings are numerical representations of text that capture semantic meaning.

### Step 1: Pull an Embedding Model

```bash
ollama pull nomic-embed-text
```

### Step 2: Generate Embeddings

Generate embeddings for a single piece of text:

```bash
ollama run nomic-embed-text "Artificial intelligence is transforming technology"
```

### Step 3: Compare Similar and Different Texts

Generate embeddings for related texts:

```bash
echo "Machine learning is changing the world" | ollama run nomic-embed-text
echo "I love pizza and pasta" | ollama run nomic-embed-text
```

**Observation**: The embedding vectors for semantically similar texts will be closer in the vector space.

## Part 3: Command-Line Chat Features

### Step 1: Single-Shot Queries

Instead of entering interactive mode, ask a single question:

```bash
ollama run gemma3 "What is the speed of light?"
```

### Step 2: Piping Input

Use pipes to send input from other commands:

```bash
echo "Translate this to French: Hello, how are you?" | ollama run gemma3
```

### Step 3: File Content Processing

Create a sample file:
```bash
cat > sample.txt << EOF
Machine learning is a subset of artificial intelligence that focuses on
building systems that can learn from data. It enables computers to improve
their performance on a specific task through experience.
EOF
```

Process the file:
```bash
cat sample.txt | ollama run gemma3 "Summarize this text in one sentence:"
```

## Part 4: Account Management

### Step 1: Sign In to Ollama

If you want to push custom models or access cloud features:

```bash
ollama signin
```

Follow the prompts to authenticate.

### Step 2: Check Sign-In Status

```bash
ollama ps
```

### Step 3: Sign Out

```bash
ollama signout
```

## Part 5: Advanced Model Management

### Step 1: Copy a Model

Create a backup or renamed version of a model:

```bash
ollama cp gemma3 gemma3-backup
```

Verify:
```bash
ollama ls
```

### Step 2: Check Model Sizes

Use your system's disk usage tools to see model storage:

**macOS/Linux**:
```bash
du -h ~/.ollama/models/
```

**Windows**:
```powershell
Get-ChildItem -Path "$env:USERPROFILE\.ollama\models" -Recurse | Measure-Object -Property Length -Sum
```

### Step 3: List Running Models with Details

```bash
ollama ps
```

This shows:
- Model name
- Size in memory
- Processor usage
- How long the model has been loaded
- When it will expire from memory

## Part 6: Working with Vision Models

### Step 1: Pull a Vision-Capable Model

```bash
ollama pull llava
```

### Step 2: Analyze an Image

Download a sample image or use one from your computer:

```bash
ollama run llava "What's in this image? /path/to/your/image.jpg"
```

Replace `/path/to/your/image.jpg` with an actual image path on your system.

### Step 3: Multi-Modal Interaction

Try asking questions about the image:

```bash
ollama run llava "Describe the colors and objects in this image. /path/to/your/image.jpg"
```

## Part 7: Model Parameters and Options

### Understanding Parameters

Different models can be configured with various parameters at runtime.

### Step 1: Setting Temperature

Temperature controls creativity (0.0 = focused, 1.0 = creative):

```bash
ollama run gemma3 --temperature 0.1 "Write a technical description of a computer"
ollama run gemma3 --temperature 0.9 "Write a technical description of a computer"
```

Compare the outputs!

## Exercises

### Exercise 1: Model Comparison Matrix

Create a comparison table with at least 3 different models:

| Model | Size | Speed | Quality | Best Use Case |
|-------|------|-------|---------|---------------|
| gemma3 | | | | |
| llama3.2 | | | | |
| mistral | | | | |

Test each model with the same prompts and fill in the table.

### Exercise 2: Embedding Similarity

1. Generate embeddings for these sentences:
   - "The cat sat on the mat"
   - "A feline rested on the rug"
   - "Python is a programming language"

2. Based on the embedding output, which two sentences are most similar?

### Exercise 3: Batch Processing

Create a file with 5 different questions (`questions.txt`), one per line:

```text
What is the capital of Japan?
Explain quantum computing briefly.
Write a haiku about the ocean.
What causes seasons on Earth?
Define machine learning.
```

Process all questions:
```bash
while read question; do
    echo "Q: $question"
    echo "$question" | ollama run gemma3
    echo "---"
done < questions.txt
```

### Exercise 4: Vision Analysis Challenge

Find 3 different types of images (a landscape, a diagram/chart, and text/document) and analyze them with a vision model. Document what the model understands well and where it struggles.

## Lab Questions

1. What is the difference between `llama3.2:latest` and `llama3.2:3b`?
2. What information is included in a model's Modelfile?
3. How are embeddings useful in AI applications?
4. What is the purpose of the `ollama ps` command?
5. When would you use a vision model versus a text-only model?
6. What happens when you set temperature to 0 versus 1?

## Advanced Challenges

### Challenge 1: Model Performance Testing

Create a script that:
1. Measures the time taken for a model to respond to a query
2. Tests with different model sizes
3. Records the results

Hint (Bash):
```bash
time echo "What is artificial intelligence?" | ollama run gemma3
```

### Challenge 2: Custom Workflow

Design a workflow that:
1. Takes an image as input
2. Uses a vision model to describe it
3. Uses a text model to create a creative story based on the description

## Troubleshooting

### Issue: Model takes too long to load
- **Solution**: Smaller models load faster; consider using quantized versions

### Issue: Embeddings output is hard to read
- **Solution**: Pipe the output to a file for analysis
  ```bash
  ollama run nomic-embed-text "text" > embeddings.json
  ```

### Issue: Vision model can't find image
- **Solution**: Use absolute paths instead of relative paths

## Summary

In this lab, you learned how to:
- Discover and understand model variants and tags
- Generate and use embeddings
- Perform single-shot queries and batch processing
- Work with vision models and images
- Manage model lifecycle and resources
- Configure model parameters for different use cases

## Next Steps

Continue to **Lab 3: Using the Ollama API** to learn how to integrate Ollama into applications using REST API calls.

