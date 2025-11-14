# Omar's Ollama Labs - Complete Learning Path

Welcome to the [Ollama](https://ollama.com/) Labs! This comprehensive series of hands-on labs will take you from beginner to advanced user of [Ollama](https://ollama.com/), a powerful tool for running large language models (LLMs) and small language models (SLMs) locally on your machine.

## 🎯 What You'll Learn

By completing these labs, you'll master:
- [Installing](https://ollama.com/download) and configuring [Ollama](https://ollama.com/)
- Running and managing AI models locally
- Building applications with Python
- Creating custom AI assistants
- Implementing advanced features like tool calling and vision processing

## 📚 Lab Overview

### [Lab 1: Installation and Basics](lab-01-installation-and-basics.md)
**Duration:** 10-15 minutes  
**Difficulty:** Beginner

Start your journey by installing [Ollama](https://ollama.com/) and running your first AI model. You'll learn:
- How to install Ollama on macOS, Windows, or Linux
- Downloading and running your first model
- Basic chat interactions and commands
- Managing models (loading, stopping, removing)

**Prerequisites:** None - perfect for beginners!

---

### [Lab 2: CLI Advanced Operations](lab-02-cli-advanced.md)
**Duration:** 20-30 minutes  
**Difficulty:** Beginner to Intermediate

Master the command-line interface with advanced features:
- Exploring different [model variants and tags](https://ollama.com/docs/tags)
- Working with [embeddings](https://ollama.com/docs/embeddings) for semantic similarity
- Using [vision models](https://ollama.com/docs/vision) to analyze images
- Batch processing and automation
- Configuring model parameters (temperature, context window)

**Prerequisites:** Completed [Lab 1](lab-01-installation-and-basics.md)

---

### [Lab 3: REST API](lab-03-rest-api.md)
**Duration:** 45-60 minutes  
**Difficulty:** Intermediate

Learn to integrate Ollama into applications using HTTP requests:
- Understanding the Ollama REST API
- Text generation and chat endpoints
- JSON mode for structured outputs
- Embeddings API for semantic search
- Model management via API
- Building scripts with curl and API calls

**Prerequisites:** 
- Completed [Lab 1](lab-01-installation-and-basics.md) and [Lab 2](lab-02-cli-advanced.md)
- Basic understanding of HTTP and REST APIs
- Familiarity with [JSON](https://www.json.org/json-en.html)

---

### [Lab 4: Python SDK](lab-04-python-sdk.md)
**Duration:** 60-75 minutes  
**Difficulty:** Intermediate

Build Python applications using the official Ollama library:
- Installing and using the Python SDK
- Creating interactive chatbots
- Streaming responses in real-time
- Working with embeddings for similarity search
- Building practical applications (document summarizer, code explainer)
- Error handling and best practices

**Prerequisites:**
- Completed [Lab 1](lab-01-installation-and-basics.md), [Lab 2](lab-02-cli-advanced.md), and [Lab 3](lab-03-rest-api.md)
- [Python](https://www.python.org/) 3.8+ installed
- Basic [Python](https://www.python.org/) programming knowledge

**Example Projects:**
- Interactive chatbot with conversation history
- Document summarization tool
- Code explanation assistant
- Sentiment analyzer

---

### [Lab 5: Custom Models with Modelfiles](lab-05-modelfiles.md)
**Duration:** 45-60 minutes  
**Difficulty:** Intermediate to Advanced

Create specialized AI assistants tailored to your needs:
- Understanding Modelfiles
- Customizing system prompts and personalities
- Adjusting model parameters for different use cases
- Few-shot learning with example messages
- Building domain-specific assistants (medical, legal, technical)

**Prerequisites:**
- Completed [Labs 1](lab-01-installation-and-basics.md), [Lab 2](lab-02-cli-advanced.md),  [Lab 3](lab-03-rest-api.md), and [Lab 4](lab-04-python-sdk.md)
- Understanding of model parameters

**Example Custom Models:**
- Technical documentation assistant
- Creative writing helper
- Code review expert
- Language tutor
- Personal productivity assistant

---

### [Lab 6: Tool Calling and Function Integration](lab-06-tool-calling.md)
**Duration:** 60-75 minutes  
**Difficulty:** Advanced

Extend model capabilities with external tools and functions:
- Understanding tool calling (function calling)
- Creating single and multiple tool integrations
- Building agent loops for multi-step reasoning
- Parallel tool execution
- Real-world integrations (APIs, databases, file systems)
- Security best practices

**Prerequisites:**
- Completed [Labs 1](lab-01-installation-and-basics.md), [Lab 2](lab-02-cli-advanced.md), [Lab 3](lab-03-rest-api.md), [Lab 4](lab-04-python-sdk.md), and [Lab 5](lab-05-modelfiles.md)
- Strong [Python](https://www.python.org/) programming skills
- Understanding of functions and APIs

**Example Applications:**
- Calculator agent with mathematical operations
- Weather information system
- File management assistant
- GitHub API integration
- Database query tools

---

### [Lab 7: Vision Models](lab-07-vision-models.md)
**Duration:** 45-60 minutes  
**Difficulty:** Intermediate to Advanced

Work with multimodal AI that understands both text and images:
- Setting up vision-capable models
- Image description and analysis
- Visual question answering
- OCR (text extraction from images)
- Object detection and counting
- Building practical vision applications

**Prerequisites:**
- Completed [Labs 1](lab-01-installation-and-basics.md), [Lab 2](lab-02-cli-advanced.md), [Lab 3](lab-03-rest-api.md), [Lab 4](lab-04-python-sdk.md), [Lab 5](lab-05-modelfiles.md), and [Lab 6](lab-06-tool-calling.md)
- Sample images for testing
- Understanding of [multimodal AI](https://en.wikipedia.org/wiki/Multimodal_learning) concepts

**Example Applications:**
- Image captioning service
- Visual question answering system
- Document scanner with OCR
- Photo organization assistant
- Image-to-story generator

---

## 🚀 Getting Started

### Recommended Learning Path

1. **Complete the labs in order** - Each lab builds on concepts from previous ones
2. **Do all exercises** - Hands-on practice is essential
3. **Experiment freely** - Try variations and explore beyond the examples
4. **Build projects** - Apply what you learn to real-world problems

### Time Commitment

- **Minimum:** ~2 hours (just following the main content)
- **Recommended:** ~4-6 hours (including exercises and experimentation)
- **Mastery:** ~6-8 hours (including all challenges and projects)



## 📖 How to Use These Labs

### For Self-Learners

1. Start with Lab 1 and progress sequentially
2. Complete all exercises before moving to the next lab
3. Answer the lab questions to test your understanding
4. Attempt the advanced challenges when ready

### For Instructors

These labs are designed for:
- University courses on AI/ML
- Corporate training programs
- Bootcamps and workshops
- Self-paced online courses

Each lab includes:
- Clear learning objectives
- Step-by-step instructions
- Hands-on exercises
- Assessment questions
- Advanced challenges
- Troubleshooting guides

### For Quick Reference

Each lab is self-contained with:
- Complete code examples
- Troubleshooting sections
- Best practices
- Links to relevant documentation

## 🛠️ What You'll Build

Throughout these labs, you'll create:

- **Lab 1:** Basic chat applications
- **Lab 2:** Batch processing scripts
- **Lab 3:** API integration scripts
- **Lab 4:** Interactive chatbot, document summarizer, code explainer
- **Lab 5:** Custom AI assistants with specialized personalities
- **Lab 6:** Tool-using agents (calculator, file manager, API integrator)
- **Lab 7:** Vision applications (image captioning, OCR, visual Q&A)

## 💡 Tips for Success

1. **Take Your Time:** Don't rush through the labs - understanding is more important than speed
2. **Experiment:** Modify the examples and see what happens
3. **Debug Actively:** When something doesn't work, use it as a learning opportunity
4. **Ask Questions:** Use the lab questions to guide your understanding
5. **Build Projects:** Apply concepts to your own project ideas
6. **Join [the Community](https://docs.ollama.com/#community):** Engage with other Ollama users and share your work

## 📚 Additional Resources

- **Ollama Website:** https://ollama.com/
- **Ollama Documentation:** https://docs.ollama.com/
- **Ollama GitHub:** https://github.com/ollama/ollama

## 📝 Lab Structure

Each lab follows a consistent structure:

- **Objective:** What you'll learn
- **Prerequisites:** What you need before starting
- **Estimated Time:** How long the lab takes
- **Step-by-Step Instructions:** Detailed walkthrough
- **Exercises:** Hands-on practice activities
- **Lab Questions:** Test your understanding
- **Advanced Challenges:** Push your skills further
- **Troubleshooting:** Common issues and solutions
- **Summary:** Key takeaways
- **Next Steps:** What to do next

## 🎓 Learning Outcomes

After completing all labs, you will be able to:

✅ Install and configure Ollama on any platform  
✅ Manage and run various AI models locally  
✅ Use the CLI for advanced operations  
✅ Integrate Ollama via REST API  
✅ Build Python applications with the Ollama SDK  
✅ Create custom AI assistants with Modelfiles  
✅ Implement tool calling for extended capabilities  
✅ Work with vision models for image analysis  
✅ Build production-ready AI applications  
✅ Apply best practices for security and performance  

## 🚀 Start Your Journey
Jump directly to the [first lab](lab-01-installation-and-basics.md) to get started!
