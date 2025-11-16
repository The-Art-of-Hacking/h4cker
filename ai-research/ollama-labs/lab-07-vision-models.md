# Lab 7: Vision Models - Working with Images

## Objective
In this lab, you will learn how to work with vision-capable models in Ollama. You'll process images, ask questions about visual content, build multimodal applications, and understand the capabilities and limitations of vision models.

## Prerequisites
- Completed Labs 1-6
- Ollama installed and running
- Python 3.8+ with Ollama library
- Sample images to work with
- Understanding of multimodal AI concepts

## Estimated Time
60-75 minutes

## Part 1: Setting Up Vision Models

### Step 1: Pull a Vision-Capable Model

```bash
ollama pull llava
```

Alternative models with vision capabilities:
```bash
ollama pull gemma3  # Also supports vision
ollama pull bakllava
```

### Step 2: Prepare Sample Images

Download or prepare some sample images for testing:

```bash
# Download a sample image
curl -L -o cat.jpg "https://upload.wikimedia.org/wikipedia/commons/3/3a/Cat03.jpg"
curl -L -o chart.png "https://upload.wikimedia.org/wikipedia/commons/thumb/1/1a/24_hour_digital_clock.svg/800px-24_hour_digital_clock.svg.png"
```

Or use your own images from your computer.

## Part 2: Basic Image Analysis (CLI)

### Step 1: Describe an Image

```bash
ollama run llava "What's in this image? ./cat.jpg"
```

### Step 2: Ask Specific Questions

```bash
ollama run llava "What color is the cat in this image? ./cat.jpg"
ollama run llava "Is the cat indoors or outdoors? ./cat.jpg"
```

### Step 3: Count Objects

```bash
ollama run llava "How many animals are in this image? ./cat.jpg"
```

## Part 3: Vision Models with Python

### Step 1: Basic Image Description

Create `describe_image.py`:

```python
from ollama import chat

# Path to your image
image_path = input("Enter path to image: ")

response = chat(
    model='llava',
    messages=[
        {
            'role': 'user',
            'content': 'Describe this image in detail.',
            'images': [image_path],
        }
    ],
)

print("Description:")
print(response.message.content)
```

Run it:
```bash
python describe_image.py
```

### Step 2: Interactive Image Q&A

Create `image_qa.py`:

```python
from ollama import chat

image_path = input("Enter path to image: ")
print(f"Loaded image: {image_path}")
print("Ask questions about the image (type 'quit' to exit)\n")

messages = []

while True:
    question = input("You: ")
    
    if question.lower() in ['quit', 'exit']:
        break
    
    messages.append({
        'role': 'user',
        'content': question,
        'images': [image_path]
    })
    
    response = chat(model='llava', messages=messages)
    
    print(f"Assistant: {response.message.content}\n")
    
    messages.append(response.message)
```

### Step 3: Batch Image Processing

Create `batch_image_processor.py`:

```python
from ollama import chat
import os
from pathlib import Path

def analyze_image(image_path, prompt="Describe this image briefly"):
    """Analyze a single image"""
    try:
        response = chat(
            model='llava',
            messages=[{
                'role': 'user',
                'content': prompt,
                'images': [image_path]
            }]
        )
        return response.message.content
    except Exception as e:
        return f"Error: {str(e)}"

def process_directory(directory, output_file="analysis.txt"):
    """Process all images in a directory"""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    
    with open(output_file, 'w') as f:
        for file_path in Path(directory).rglob('*'):
            if file_path.suffix.lower() in image_extensions:
                print(f"Processing: {file_path}")
                
                description = analyze_image(str(file_path))
                
                f.write(f"File: {file_path}\n")
                f.write(f"Description: {description}\n")
                f.write("-" * 80 + "\n")
    
    print(f"Analysis saved to {output_file}")

if __name__ == "__main__":
    directory = input("Enter directory path: ")
    process_directory(directory)
```

## Part 4: Vision with Base64 Encoding

### Step 1: Using Base64 Encoded Images

Create `base64_vision.py`:

```python
from ollama import chat
import base64
from pathlib import Path

def encode_image(image_path):
    """Encode image to base64"""
    with open(image_path, 'rb') as f:
        return base64.b64encode(f.read()).decode('utf-8')

# Encode the image
image_path = "cat.jpg"
encoded_image = encode_image(image_path)

response = chat(
    model='llava',
    messages=[{
        'role': 'user',
        'content': 'What animal is in this image?',
        'images': [encoded_image]
    }]
)

print(response.message.content)
```

### Step 2: Using Raw Bytes

Create `bytes_vision.py`:

```python
from ollama import chat
from pathlib import Path

image_path = Path("cat.jpg")
image_bytes = image_path.read_bytes()

response = chat(
    model='llava',
    messages=[{
        'role': 'user',
        'content': 'Describe the main subject of this image.',
        'images': [image_bytes]
    }]
)

print(response.message.content)
```

## Part 5: Specialized Vision Tasks

### Step 1: OCR (Text Extraction)

Create `ocr_tool.py`:

```python
from ollama import chat

def extract_text_from_image(image_path):
    """Extract text from an image using vision model"""
    
    response = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': '''Extract all text visible in this image. 
            Provide the text exactly as it appears, maintaining any formatting.
            If there is no text, say "No text found."''',
            'images': [image_path]
        }]
    )
    
    return response.message.content

# Test with an image containing text
image_path = input("Enter path to image with text: ")
extracted_text = extract_text_from_image(image_path)

print("Extracted Text:")
print("="*50)
print(extracted_text)
```

### Step 2: Object Detection and Counting

Create `object_counter.py`:

```python
from ollama import chat

def count_objects(image_path, object_type="all objects"):
    """Count specific objects in an image"""
    
    prompt = f"""Please analyze this image and count the {object_type}. 
    Provide your answer in this format:
    - Object type: count
    - Object type: count
    
    Be specific and accurate."""
    
    response = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': prompt,
            'images': [image_path]
        }]
    )
    
    return response.message.content

# Example usage
image_path = input("Enter image path: ")
object_type = input("What objects to count? (or press Enter for all): ") or "all objects"

result = count_objects(image_path, object_type)
print(result)
```

### Step 3: Image Comparison

Create `compare_images.py`:

```python
from ollama import chat

def compare_images(image1_path, image2_path):
    """Compare two images and describe differences"""
    
    # Analyze first image
    response1 = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': 'Describe the key elements of this image concisely.',
            'images': [image1_path]
        }]
    )
    
    # Analyze second image
    response2 = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': 'Describe the key elements of this image concisely.',
            'images': [image2_path]
        }]
    )
    
    # Compare descriptions
    comparison_prompt = f"""Compare these two image descriptions:

Image 1: {response1.message.content}

Image 2: {response2.message.content}

What are the main similarities and differences?"""
    
    comparison = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': comparison_prompt
        }]
    )
    
    return {
        'image1_description': response1.message.content,
        'image2_description': response2.message.content,
        'comparison': comparison.message.content
    }

# Example usage
img1 = input("Enter first image path: ")
img2 = input("Enter second image path: ")

result = compare_images(img1, img2)

print("\nImage 1:")
print(result['image1_description'])
print("\nImage 2:")
print(result['image2_description'])
print("\nComparison:")
print(result['comparison'])
```

## Part 6: Multimodal Conversations

### Step 1: Multi-Turn Image Discussion

Create `image_conversation.py`:

```python
from ollama import chat

image_path = input("Enter image path: ")

messages = []

print("Starting conversation about the image...")
print("Type 'quit' to exit\n")

while True:
    user_input = input("You: ")
    
    if user_input.lower() in ['quit', 'exit']:
        break
    
    # Include image in every message for context
    messages.append({
        'role': 'user',
        'content': user_input,
        'images': [image_path]
    })
    
    stream = chat(model='llava', messages=messages, stream=True)
    
    print("Assistant: ", end='', flush=True)
    full_response = ""
    
    for chunk in stream:
        content = chunk['message']['content']
        full_response += content
        print(content, end='', flush=True)
    
    print()  # New line
    
    messages.append({
        'role': 'assistant',
        'content': full_response
    })
```

### Step 2: Multiple Images in One Query

Create `multi_image_analysis.py`:

```python
from ollama import chat

def analyze_multiple_images(image_paths, question):
    """Analyze multiple images together"""
    
    response = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': question,
            'images': image_paths
        }]
    )
    
    return response.message.content

# Example usage
print("Enter image paths (one per line, empty line to finish):")
image_paths = []

while True:
    path = input()
    if not path:
        break
    image_paths.append(path)

if image_paths:
    question = input("\nWhat would you like to know about these images? ")
    result = analyze_multiple_images(image_paths, question)
    print("\nAnalysis:")
    print(result)
else:
    print("No images provided.")
```

## Part 7: Practical Applications

### Step 1: Image Captioning Service

Create `image_caption_service.py`:

```python
from ollama import chat
import json
from pathlib import Path

def generate_caption(image_path, style="descriptive"):
    """Generate caption for an image"""
    
    styles = {
        "descriptive": "Provide a detailed, descriptive caption for this image.",
        "concise": "Provide a brief, one-sentence caption for this image.",
        "social": "Create an engaging social media caption for this image.",
        "technical": "Provide a technical description of this image."
    }
    
    prompt = styles.get(style, styles["descriptive"])
    
    response = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': prompt,
            'images': [image_path]
        }]
    )
    
    return response.message.content

def batch_caption(directory, style="descriptive", output_json="captions.json"):
    """Generate captions for all images in directory"""
    
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    results = {}
    
    for file_path in Path(directory).rglob('*'):
        if file_path.suffix.lower() in image_extensions:
            print(f"Captioning: {file_path}")
            caption = generate_caption(str(file_path), style)
            results[str(file_path)] = caption
    
    with open(output_json, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Captions saved to {output_json}")
    return results

# Example usage
if __name__ == "__main__":
    choice = input("Caption single image (s) or directory (d)? ")
    
    if choice.lower() == 's':
        img = input("Image path: ")
        style = input("Style (descriptive/concise/social/technical): ") or "descriptive"
        print("\nCaption:", generate_caption(img, style))
    else:
        directory = input("Directory path: ")
        style = input("Style (descriptive/concise/social/technical): ") or "descriptive"
        batch_caption(directory, style)
```

### Step 2: Visual Question Answering System

Create `visual_qa_system.py`:

```python
from ollama import chat

class VisualQA:
    def __init__(self, model='llava'):
        self.model = model
        self.current_image = None
        self.conversation_history = []
    
    def load_image(self, image_path):
        """Load an image for analysis"""
        self.current_image = image_path
        self.conversation_history = []
        print(f"Loaded: {image_path}")
    
    def ask(self, question):
        """Ask a question about the current image"""
        if not self.current_image:
            return "No image loaded. Use load_image() first."
        
        self.conversation_history.append({
            'role': 'user',
            'content': question,
            'images': [self.current_image]
        })
        
        response = chat(
            model=self.model,
            messages=self.conversation_history
        )
        
        self.conversation_history.append(response.message)
        return response.message.content
    
    def get_summary(self):
        """Get a summary of the conversation"""
        if not self.conversation_history:
            return "No conversation yet."
        
        summary_prompt = "Summarize our conversation about this image."
        return self.ask(summary_prompt)

# Interactive usage
qa = VisualQA()

print("Visual QA System")
print("Commands: load <path>, ask <question>, summary, quit")

while True:
    cmd = input("\n> ").strip()
    
    if cmd.lower() == 'quit':
        break
    elif cmd.startswith('load '):
        image_path = cmd[5:].strip()
        qa.load_image(image_path)
    elif cmd.startswith('ask '):
        question = cmd[4:].strip()
        answer = qa.ask(question)
        print(f"Answer: {answer}")
    elif cmd == 'summary':
        print(qa.get_summary())
    else:
        print("Unknown command")
```

### Step 3: Image-to-Story Generator

Create `image_story_generator.py`:

```python
from ollama import chat

def generate_story_from_image(image_path, story_type="creative"):
    """Generate a story based on an image"""
    
    story_types = {
        "creative": "Write a creative, imaginative story inspired by this image. Make it engaging and descriptive.",
        "realistic": "Write a realistic story about what might be happening in this image.",
        "children": "Write a short, fun children's story based on this image.",
        "scifi": "Write a science fiction story inspired by elements in this image."
    }
    
    # First, get image description
    desc_response = chat(
        model='llava',
        messages=[{
            'role': 'user',
            'content': 'Describe this image in detail, noting key elements, mood, and setting.',
            'images': [image_path]
        }]
    )
    
    # Then generate story using text model for better narrative
    story_prompt = f"""{story_types.get(story_type, story_types['creative'])}

Based on this image description: {desc_response.message.content}"""
    
    story_response = chat(
        model='gemma3',  # Using text model for better story writing
        messages=[{
            'role': 'user',
            'content': story_prompt
        }]
    )
    
    return {
        'description': desc_response.message.content,
        'story': story_response.message.content
    }

# Example usage
image_path = input("Enter image path: ")
story_type = input("Story type (creative/realistic/children/scifi): ") or "creative"

result = generate_story_from_image(image_path, story_type)

print("\nImage Description:")
print("="*60)
print(result['description'])
print("\nGenerated Story:")
print("="*60)
print(result['story'])
```

## Exercises

### Exercise 1: Accessibility Tool

Create a tool that generates detailed image descriptions for visually impaired users:
- Describes scene composition
- Identifies all objects and their positions
- Notes colors and textures
- Describes any text present

### Exercise 2: Product Analyzer

Build a product analysis tool that:
- Identifies products in images
- Describes features
- Estimates condition (new/used)
- Suggests improvements for product photography

### Exercise 3: Chart and Graph Reader

Create a tool that:
- Extracts data from charts and graphs
- Describes trends
- Identifies key data points
- Converts visual data to text/CSV

### Exercise 4: Photo Organization Assistant

Build a system that:
- Analyzes photos in a directory
- Generates descriptive tags
- Groups similar images
- Creates searchable metadata

### Exercise 5: Visual Content Moderator

Create a content moderation tool that:
- Analyzes images for specific content
- Flags potentially inappropriate content
- Provides detailed reasoning
- Suggests content ratings

## Lab Questions

1. What types of tasks are vision models good at?
2. What are the limitations of current vision models?
3. How does image quality affect model performance?
4. When should you use base64 encoding vs. file paths?
5. How can you improve accuracy for specific vision tasks?
6. What are the privacy considerations when using vision models?

## Advanced Challenges

### Challenge 1: Visual Search Engine

Build a visual search system that:
1. Indexes images with embeddings
2. Searches by image similarity
3. Searches by text descriptions
4. Combines visual and text search

### Challenge 2: Document Scanner

Create a document processing system that:
1. Extracts text from documents
2. Identifies document type
3. Extracts key information (dates, names, amounts)
4. Organizes by category

### Challenge 3: Visual Tutorial Generator

Build a system that:
1. Takes a series of images
2. Analyzes each step
3. Generates step-by-step tutorial
4. Creates descriptive captions

## Best Practices

### 1. Image Quality
- Use clear, high-resolution images
- Ensure good lighting
- Avoid overly complex scenes
- Test with various image qualities

### 2. Prompt Engineering for Vision
- Be specific about what you want to know
- Ask about one thing at a time
- Provide context when needed
- Use follow-up questions for clarification

### 3. Error Handling
```python
def safe_vision_call(image_path, prompt):
    try:
        response = chat(
            model='llava',
            messages=[{
                'role': 'user',
                'content': prompt,
                'images': [image_path]
            }]
        )
        return response.message.content
    except FileNotFoundError:
        return "Error: Image file not found"
    except Exception as e:
        return f"Error: {str(e)}"
```

### 4. Performance
- Cache descriptions for repeated queries
- Batch process when possible
- Use appropriate image sizes
- Consider using async for multiple images

## Limitations and Considerations

### Model Limitations
- May misidentify objects occasionally
- Struggles with very small text
- Can be sensitive to image quality
- May not understand very abstract or artistic images
- Limited by training data

### Privacy and Ethics
- Be cautious with personal photos
- Consider privacy implications
- Don't use for surveillance without consent
- Be aware of biases in vision models

## Troubleshooting

### Issue: Model can't see the image
- **Solution**: Check file path, try absolute path

### Issue: Poor image descriptions
- **Solution**: Use higher quality images, try different prompts

### Issue: Slow processing
- **Solution**: Reduce image size, use appropriate model

### Issue: Incorrect text extraction
- **Solution**: Ensure text is clear and large enough, try different prompts

## Summary

In this lab, you learned how to:
- Work with vision-capable models in Ollama
- Process images using CLI and Python
- Build multimodal applications
- Extract text from images (OCR)
- Create specialized vision tools
- Combine vision and text models
- Handle multiple images and conversations
- Implement practical vision applications

## Conclusion

Congratulations on completing all 7 Ollama labs! You now have comprehensive knowledge of:
- Installing and using Ollama
- Working with models via CLI and API
- Programming with Python SDK
- Creating custom models
- Implementing tool calling
- Working with vision models

Continue exploring and building with Ollama!

