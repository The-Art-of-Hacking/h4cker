# Lab 5: Creating Custom Models with Modelfiles

## Objective
In this lab, you will learn how to create custom models using Modelfiles. You'll customize system prompts, adjust parameters, set templates, and create specialized models for specific tasks. This allows you to tailor models to your exact needs.

## Prerequisites
- Completed Labs 1-4
- Ollama installed and running
- At least one base model downloaded (e.g., `gemma3`, `llama3.2`)
- Text editor for creating Modelfiles
- Basic understanding of model parameters

## Estimated Time
60-75 minutes

## Part 1: Understanding Modelfiles

### What is a Modelfile?

A Modelfile is a blueprint for creating and customizing models in Ollama. It's similar to a Dockerfile for containers.

### Modelfile Structure

```
FROM <base-model>
PARAMETER <parameter-name> <value>
SYSTEM <system-message>
TEMPLATE <prompt-template>
MESSAGE <role> <content>
```

## Part 2: Creating Your First Custom Model

### Step 1: View an Existing Modelfile

```bash
ollama show --modelfile gemma3
```

Study the output to understand how the model is configured.

### Step 2: Create a Simple Custom Model

Create a file named `Modelfile.mario`:

```
FROM gemma3

# Set the temperature to 1 [higher is more creative, lower is more coherent]
PARAMETER temperature 1

# Set the system message
SYSTEM """
You are Mario from Super Mario Bros, acting as an assistant. 
You always speak with Italian enthusiasm and end many sentences with "Let's-a-go!" or "Mamma mia!".
You're cheerful, optimistic, and love to help people.
"""
```

### Step 3: Build the Custom Model

```bash
ollama create mario -f Modelfile.mario
```

### Step 4: Test Your Custom Model

```bash
ollama run mario
```

Try these prompts:
- "Hello! How are you?"
- "Can you help me with a programming question?"
- "Tell me about yourself"

### Step 5: Compare with Base Model

```bash
ollama run gemma3 "Hello! How are you?"
```

Notice the difference in personality!

## Part 3: Working with Parameters

### Step 1: Temperature Control

Create `Modelfile.technical`:

```
FROM gemma3

PARAMETER temperature 0.3
PARAMETER top_p 0.9

SYSTEM """
You are a technical documentation assistant. You provide clear, accurate, 
and concise technical information. You avoid speculation and stick to facts.
You format your responses with proper markdown when appropriate.
"""
```

Create the model:
```bash
ollama create technical-assistant -f Modelfile.technical
```

### Step 2: Creative Writer Model

Create `Modelfile.creative`:

```
FROM gemma3

PARAMETER temperature 0.9
PARAMETER top_k 40
PARAMETER top_p 0.95

SYSTEM """
You are a creative writing assistant. You help users write stories, poems, 
and creative content. You're imaginative, descriptive, and always suggest 
unique and interesting ideas.
"""
```

Create the model:
```bash
ollama create creative-writer -f Modelfile.creative
```

### Step 3: Context Window Size

Create `Modelfile.longcontext`:

```
FROM gemma3

PARAMETER num_ctx 8192
PARAMETER temperature 0.7

SYSTEM """
You are an assistant capable of handling long conversations and documents.
You maintain context across extended discussions.
"""
```

Create the model:
```bash
ollama create long-context -f Modelfile.longcontext
```

## Part 4: Advanced System Prompts

### Step 1: Role-Specific Assistant

Create `Modelfile.teacher`:

```
FROM gemma3

PARAMETER temperature 0.7
PARAMETER num_predict 500

SYSTEM """
You are a patient and knowledgeable teacher specializing in explaining complex 
topics to beginners. 

Your teaching style:
1. Start with simple explanations
2. Use analogies and real-world examples
3. Break down complex topics into smaller parts
4. Check for understanding
5. Encourage questions
6. Provide step-by-step guidance

Always be encouraging and make learning enjoyable.
"""
```

Create the model:
```bash
ollama create teacher -f Modelfile.teacher
```

Test it:
```bash
ollama run teacher "Explain how the internet works"
```

### Step 2: Code Review Assistant

Create `Modelfile.codereview`:

```
FROM gemma3

PARAMETER temperature 0.4
PARAMETER num_ctx 4096

SYSTEM """
You are an experienced code reviewer. When reviewing code, you:

1. Identify potential bugs or errors
2. Suggest improvements for readability and maintainability
3. Point out security concerns
4. Recommend best practices
5. Provide specific, actionable feedback

Format your reviews with clear sections:
- Summary
- Issues Found
- Suggestions
- Positive Aspects

Be constructive and educational in your feedback.
"""
```

Create and test:
```bash
ollama create code-reviewer -f Modelfile.codereview
ollama run code-reviewer
```

## Part 5: Using MESSAGE for Few-Shot Learning

### Step 1: Question Classification Model

Create `Modelfile.classifier`:

```
FROM gemma3

PARAMETER temperature 0.2

SYSTEM """
You classify user questions into categories: TECHNICAL, CREATIVE, FACTUAL, or OPINION.
Respond with only the category name.
"""

MESSAGE user Is Python better than Java?
MESSAGE assistant OPINION

MESSAGE user What is the capital of France?
MESSAGE assistant FACTUAL

MESSAGE user Write a poem about the ocean
MESSAGE assistant CREATIVE

MESSAGE user How do I fix a segmentation fault?
MESSAGE assistant TECHNICAL
```

Create and test:
```bash
ollama create question-classifier -f Modelfile.classifier
ollama run question-classifier "What causes rain?"
```

### Step 2: Sentiment Analyzer

Create `Modelfile.sentiment`:

```
FROM gemma3

PARAMETER temperature 0.1

SYSTEM """
You analyze sentiment of text. Respond with only: POSITIVE, NEGATIVE, or NEUTRAL.
"""

MESSAGE user I love this product! It's amazing!
MESSAGE assistant POSITIVE

MESSAGE user This is the worst experience ever.
MESSAGE assistant NEGATIVE

MESSAGE user The package arrived on time.
MESSAGE assistant NEUTRAL
```

Create and test:
```bash
ollama create sentiment-analyzer -f Modelfile.sentiment
```

## Part 6: Specialized Domain Models

### Step 1: Medical Information Assistant

Create `Modelfile.medical`:

```
FROM gemma3

PARAMETER temperature 0.3
PARAMETER num_ctx 4096

SYSTEM """
You are a medical information assistant. 

IMPORTANT DISCLAIMERS:
- You provide general medical information for educational purposes only
- You are NOT a substitute for professional medical advice
- You always recommend consulting healthcare professionals for medical concerns
- You never diagnose conditions or prescribe treatments

Your responses:
- Are evidence-based and reference-supported
- Use clear, accessible language
- Include relevant disclaimers
- Encourage seeking professional medical advice
"""

MESSAGE user What are the symptoms of the flu?
MESSAGE assistant The flu (influenza) typically presents with symptoms including:

- Sudden onset of fever (usually high)
- Body aches and muscle pain
- Headache
- Fatigue
- Dry cough
- Sore throat
- Sometimes nasal congestion

Important: If you're experiencing these symptoms, please consult with a healthcare 
professional for proper diagnosis and treatment. This information is for educational 
purposes only.
```

### Step 2: Legal Information Assistant

Create `Modelfile.legal`:

```
FROM gemma3

PARAMETER temperature 0.4

SYSTEM """
You are a legal information assistant providing general legal information.

DISCLAIMERS:
- You provide general legal information, not legal advice
- You are not a substitute for a qualified attorney
- Laws vary by jurisdiction
- Always recommend consulting a licensed attorney for legal matters

Your responses:
- Explain legal concepts in understandable terms
- Provide general information about legal processes
- Clarify that specific situations require professional legal counsel
- Never provide specific legal advice or represent any legal position
"""
```

## Part 7: Template Customization (Advanced)

### Step 1: Understanding Templates

Templates control how messages are formatted before being sent to the model.

View a template:
```bash
ollama show --modelfile gemma3 | grep -A 10 TEMPLATE
```

### Step 2: Custom Template

Create `Modelfile.customtemplate`:

```
FROM gemma3

TEMPLATE """
{{ if .System }}### System:
{{ .System }}
{{ end }}

{{ if .Prompt }}### User:
{{ .Prompt }}
{{ end }}

### Assistant:
"""

SYSTEM "You are a helpful AI assistant."
```

## Exercises

### Exercise 1: Personal Assistant

Create a custom model that:
1. Acts as your personal productivity assistant
2. Helps with task management
3. Provides motivation and encouragement
4. Has an energetic, positive personality

### Exercise 2: Language Tutor

Create a model that:
1. Teaches a specific language (e.g., Spanish)
2. Provides translations
3. Explains grammar rules
4. Gives practice exercises
5. Corrects mistakes constructively

### Exercise 3: Debug Assistant

Create a specialized debugging assistant that:
1. Helps identify bugs in code
2. Suggests debugging strategies
3. Explains error messages
4. Provides step-by-step debugging guidance

### Exercise 4: Data Analyst

Create a model that:
1. Helps interpret data
2. Suggests visualizations
3. Explains statistical concepts
4. Reviews data analysis approaches

### Exercise 5: Model Comparison

Create three versions of a model with different temperature settings:
- Conservative (temperature 0.2)
- Balanced (temperature 0.7)
- Creative (temperature 1.0)

Test them with the same prompts and document the differences.

## Lab Questions

1. What is the purpose of the `FROM` instruction in a Modelfile?
2. How does temperature affect model responses?
3. What is the difference between `SYSTEM` and `MESSAGE` instructions?
4. Why would you want to create a custom model instead of using a base model?
5. How can few-shot learning (MESSAGE examples) improve model behavior?
6. What are the ethical considerations when creating specialized domain models?

## Advanced Challenges

### Challenge 1: Multi-Persona Model

Create a model that can switch between different personas based on user request:
- Professional mode
- Casual mode
- Tutorial mode

Hint: Use clear instructions in the system message about persona switching.

### Challenge 2: Domain-Specific Expert

Create a highly specialized model for a specific field you're interested in:
- Include relevant few-shot examples
- Set appropriate parameters
- Add safety disclaimers if needed
- Test with various domain-specific queries

### Challenge 3: Model Family

Create a family of related models:
1. Base assistant
2. Creative variant
3. Technical variant
4. Teaching variant

All should share some common characteristics but have distinct personalities and capabilities.

## Best Practices

### 1. System Prompts
- Be specific and clear
- Include guidelines for behavior
- Set boundaries and limitations
- Define the expected output format

### 2. Parameters
- Temperature: 0.0-0.5 for factual tasks, 0.6-1.0 for creative tasks
- Use appropriate context window sizes
- Test different combinations

### 3. Few-Shot Examples
- Provide 3-5 diverse examples
- Ensure examples match your use case
- Keep examples concise but representative

### 4. Testing
- Test with various inputs
- Compare with base model
- Iterate based on results
- Document unexpected behaviors

## Troubleshooting

### Issue: Model behaves inconsistently
- **Solution**: Lower temperature, add more MESSAGE examples

### Issue: Responses too short
- **Solution**: Adjust `num_predict` parameter or modify system prompt

### Issue: Model ignores system prompt
- **Solution**: Make system prompt more explicit, add MESSAGE examples

### Issue: Custom model too slow
- **Solution**: Reduce `num_ctx` or use a smaller base model

## Summary

In this lab, you learned how to:
- Create custom models using Modelfiles
- Customize system prompts for specific behaviors
- Adjust parameters to control output characteristics
- Use MESSAGE for few-shot learning
- Create domain-specific assistants
- Implement best practices for model customization

## Next Steps

Continue to **Lab 6: Tool Calling and Function Integration** to learn how to give models access to external tools and functions.

