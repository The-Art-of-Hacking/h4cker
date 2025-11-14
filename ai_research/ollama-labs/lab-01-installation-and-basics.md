# Lab 1: Getting Started with Ollama - Installation and Basic Usage

## Objective
In this lab, you will learn how to install Ollama, download your first model, and interact with it using the command-line interface. By the end of this lab, you'll understand the basics of running and chatting with local large language models.

## Important Links
- [Ollama website](https://ollama.com/)
- [Ollama documentation](https://ollama.com/docs)
- [Ollama GitHub repository](https://github.com/ollama/ollama)

## Prerequisites
- A computer running macOS, Windows, or Linux
- At least 8GB of RAM (16GB recommended)
- At least 10GB of free disk space
- Basic familiarity with the command line/terminal

## Estimated Time
30-45 minutes

## Part 1: Installing Ollama

### Step 1: Download and Install Ollama

1. Visit [https://ollama.com/download](https://ollama.com/download)
2. Download the installer for your operating system:
   - **macOS**: Download the `.dmg` file
   - **Windows**: Download the `.exe` installer
   - **Linux**: Use the installation script (see below)

#### For Linux users:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 2: Verify Installation

After installation, open a terminal/command prompt and verify Ollama is installed:

```bash
ollama --version
```

You should see the version number displayed.

### Step 3: Check if Ollama is Running

Ollama typically starts automatically. To verify:

```bash
ollama ps
```

If Ollama isn't running, start it with:

```bash
ollama serve
```

## Part 2: Running Your First Model

### Step 1: Download a Model

Let's start with a smaller model that's great for learning. Download the `gemma3` model:

```bash
ollama pull gemma3
```

**Note**: This will download several gigabytes of data. The download time depends on your internet connection.

### Step 2: List Available Models

After the download completes, verify the model is available:

```bash
ollama ls
```

You should see `gemma3` in the list of available models.

## Part 3: Interacting with the Model

### Step 1: Start a Chat Session

Run the model in interactive mode:

```bash
ollama run gemma3
```

### Step 2: Have a Conversation

Try these prompts:

1. **Basic greeting**:
   ```
   Hello! Can you introduce yourself?
   ```

2. **Ask a question**:
   ```
   What is the capital of France?
   ```

3. **Request an explanation**:
   ```
   Explain how photosynthesis works in simple terms.
   ```

4. **Creative task**:
   ```
   Write a haiku about artificial intelligence.
   ```

### Step 3: Exit the Chat

To exit the interactive session, type:
```
/bye
```

Or press `Ctrl+D` (macOS/Linux) or `Ctrl+C` (Windows).

## Part 4: Multiline Input

### Step 1: Using Multiline Mode

Start another chat session:
```bash
ollama run gemma3
```

Try a multiline input using triple quotes:
```
"""Write a short story about a robot
learning to paint. Make it 
heartwarming and inspirational."""
```

## Part 5: Managing Models

### Step 1: View Model Information

Get detailed information about your model:

```bash
ollama show gemma3
```

### Step 2: Check Running Models

See which models are currently loaded in memory:

```bash
ollama ps
```

### Step 3: Stop a Model

To unload a model from memory:

```bash
ollama stop gemma3
```

### Step 4: Remove a Model (Optional)

If you want to free up disk space, you can remove a model:

```bash
ollama rm gemma3
```

**Note**: Don't do this if you want to continue with the remaining labs!

## Exercises

### Exercise 1: Model Comparison
1. Pull another small model: `ollama pull llama3.2`
2. Ask both models the same question and compare their responses
3. Document the differences in style, accuracy, and response time

### Exercise 2: Use Cases
For each of the following tasks, interact with the model and evaluate its performance:
1. Code explanation (paste a simple Python function and ask it to explain)
2. Language translation (translate a sentence to another language)
3. Math problem solving (give it a word problem)
4. Creative writing (ask for a poem or story)

### Exercise 3: Model Management
1. Check how much disk space your models are using (hint: check `ollama ls`)
2. Experiment with the `ollama ps` command while a model is running
3. Stop and restart a model, observing the load time

## Lab Questions

Answer these questions based on your experience:

1. What is the size of the `gemma3` model you downloaded?
2. How long did it take for the model to load the first time you ran it?
3. What happens when you ask the model a question about current events?
4. What are the advantages of running models locally versus using cloud-based APIs?
5. What limitations did you notice when interacting with the model?

## Troubleshooting

### Issue: "ollama: command not found"
- **Solution**: Restart your terminal or add Ollama to your PATH manually

### Issue: Model download is very slow
- **Solution**: Check your internet connection; large models can take time to download

### Issue: "Out of memory" errors
- **Solution**: Try a smaller model or close other applications to free up RAM

### Issue: Model responses are very slow
- **Solution**: This is normal for larger models on systems without GPUs. Consider using a smaller model.

## Summary

In this lab, you learned how to:
- Install Ollama on your system
- Download and manage language models
- Interact with models using the command-line interface
- Use multiline input for complex prompts
- Manage model resources (loading, stopping, removing)

## Next Steps

Continue to **Lab 2: Working with the CLI** to learn advanced command-line features and model management techniques.

