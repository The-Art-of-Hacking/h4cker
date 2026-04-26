# Prompt Engineering Resources

## Prompting Guide
This is a great resource for prompting LLMs:
- https://www.promptingguide.ai

## Tools and Sample Prompt Repositories

|  Resource| Description  | Link |
| :-------------------- | :----------: | :----------: |
| **LlamaIndex** | LlamaIndex is a project consisting of a set of data structures designed to make it easier to use large external knowledge bases with LLMs. | [[Github]](https://github.com/jerryjliu/gpt_index) |
| **Promptify** | Solve NLP Problems with LLM's & Easily generate different NLP Task prompts for popular generative models like GPT, PaLM, and more with Promptify | [[Github]](https://github.com/promptslab/Promptify) |
| **Arize-Phoenix** | Open-source tool for ML observability that runs in your notebook environment. Monitor and fine tune LLM, CV and Tabular Models. | [[Github]](https://github.com/Arize-ai/phoenix) |
| **Better Prompt** | Test suite for LLM prompts before pushing them to PROD | [[Github]](https://github.com/krrishdholakia/betterprompt) |
| **CometLLM** | Log, visualize, and evaluate your LLM prompts, prompt templates, prompt variables, metadata, and more. | [[Github]](https://github.com/comet-ml/comet-llm) |
| **Embedchain** | Framework to create ChatGPT like bots over your dataset | [[Github]](https://github.com/embedchain/embedchain) |
| **Interactive Composition Explorerx** | ICE is a Python library and trace visualizer for language model programs. | [[Github]](https://github.com/oughtinc/ice) |
| **Haystack** | Open source NLP framework to interact with your data using LLMs and Transformers. | [[Github]](https://github.com/deepset-ai/haystack) |
| **LangChainx** | Building applications with LLMs through composability | [[Github]](https://github.com/hwchase17/langchain) |
| **OpenPrompt** | An Open-Source Framework for Prompt-learning | [[Github]](https://github.com/thunlp/OpenPrompt) |
| **Prompt Engine** | This repo contains an NPM utility library for creating and maintaining prompts for Large Language Models (LLMs). | [[Github]](https://github.com/microsoft/prompt-engine) |
| **PromptInject** | PromptInject is a framework that assembles prompts in a modular fashion to provide a quantitative analysis of the robustness of LLMs to adversarial prompt attacks. | [[Github]](https://github.com/agencyenterprise/PromptInject) |
| **Prompts AI** | Advanced playground for GPT-3 | [[Github]](https://github.com/sevazhidkov/prompts-ai) |
| **Prompt Source** | PromptSource is a toolkit for creating, sharing and using natural language prompts. | [[Github]](https://github.com/bigscience-workshop/promptsource) |
| **ThoughtSource** | A framework for the science of machine thinking | [[Github]](https://github.com/OpenBioLink/ThoughtSource) |
| **PROMPTMETHEUS** | One-shot Prompt Engineering Toolkit | [[Tool]](https://promptmetheus.com) |
| **AI Config** | An Open-Source configuration based framework for building applications with LLMs | [[Github]](https://github.com/lastmile-ai/aiconfig) | 
| **LastMile AI** | Notebook-like playground for interacting with LLMs across different modalities (text, speech, audio, image) | [[Tool]](https://lastmileai.dev/) |
| **XpulsAI** | Effortlessly build scalable AI Apps. AutoOps platform for AI & ML | [[Tool]](https://xpuls.ai/) |
| **Agenta** | Agenta is an open-source LLM developer platform with the tools for prompt management, evaluation, human feedback, and deployment all in one place.  | [[Github]](https://github.com/agenta-ai/agenta) |
| **Promptotype** | Develop, test, and monitor your LLM { structured } tasks | [[Tool]](https://www.promptotype.io) |

## Tutorials and Videos

### Introduction to Prompt Engineering

- [Prompt Engineering 101 - Introduction and resources](https://www.linkedin.com/pulse/prompt-engineering-101-introduction-resources-amatriain)
- [Prompt Engineering 101](https://humanloop.com/blog/prompt-engineering-101)
- [Prompt Engineering Guide by SudalaiRajkumar](https://github.com/SudalaiRajkumar/Talks_Webinars/blob/master/Slides/PromptEngineering_20230208.pdf)

### Beginner's Guide to Generative Language Models

- [A beginner-friendly guide to generative language models - LaMBDA guide](https://aitestkitchen.withgoogle.com/how-lamda-works)
- [Generative AI with Cohere: Part 1 - Model Prompting](https://txt.cohere.ai/generative-ai-part-1)

### Best Practices for Prompt Engineering
The following are some best practices for prompt engineering.

### General Principles of Effective Prompt Engineering (Applies Everywhere)

Before diving into framework-specific techniques, let's recap some universal best practices:

1.  **Be Clear and Specific**:
    * **Avoid Ambiguity**: Leave no room for interpretation. Instead of "Write a summary," say "Summarize the provided text in exactly 3 bullet points, focusing on key findings for a scientific audience."
    * **Define Output Format**: Explicitly state the desired format (e.g., JSON, markdown list, a specific sentence structure). Use examples!
    * **Set Length Constraints**: Specify length in terms of words, sentences, paragraphs, or tokens.
2.  **Provide Sufficient Context**:
    * Always include all necessary background information for the task. For RAG, this means the retrieved documents.
    * Clearly delineate between instructions and context (e.g., using delimiters like `---` or `###`).
3.  **Define a Persona and Tone (System Prompts)**:
    * Instruct the LLM on *who* it is and *how* it should behave. "You are a helpful customer support agent." "You are a concise technical writer."
    * Maintain consistency in tone throughout the interaction.
4.  **Break Down Complex Tasks (Chain-of-Thought)**:
    * For multi-step problems, ask the LLM to "think step-by-step" or provide intermediate reasoning. This often dramatically improves accuracy.
    * Guide the LLM through a sequence of smaller sub-tasks.
5.  **Use Examples (Few-Shot Prompting)**:
    * Providing a few input-output examples directly in the prompt can teach the LLM the desired pattern, format, and behavior without requiring fine-tuning. This is especially useful for specific data extraction or formatting tasks.
6.  **Iterate and Test**:
    * Prompt engineering is an iterative process. Start simple, test, observe results (ideally with LangSmith!), and refine.
    * Keep a history of your prompts and their performance.
7.  **Positive Constraints**:
    * Instead of telling the LLM "don't do X," tell it "do Y" instead. For example, instead of "don't be too verbose," say "be concise."

---

#### General Principles Prompt Engineering for AI Agent Applications

Beyond framework specifics, agents demand even more sophisticated prompting:

1.  **Goal-Oriented Prompting**:
    * Always clearly state the agent's overall goal and mission in the system prompt. This acts as its north star.
    * "Your primary objective is to book a round-trip flight from {origin} to {destination} for {date}."

2.  **"Thought" or "Reasoning" Prompts (Chain-of-Thought Reinforcement)**:
    * Encourage the agent to articulate its thought process before taking an action. This makes debugging easier and often improves reasoning quality.
    * "Thought: I need to determine the best tool to use. First, I will..."
    * "Reasoning: Based on the previous observation, the search results indicate X, but I still need to verify Y. Therefore, my next step is Z."

3.  **Tool Use Specification**:
    * For agents using `tool_calling` capabilities, the prompt must accurately reflect the available tools, their precise names, descriptions, and expected parameters. Modern LLMs are often fine-tuned for a specific tool-calling format, so consistency is key.
    * Example (often automatically generated by frameworks but good to understand):
        ```
        Available tools:
        - search_web(query: str): Searches the internet for information.
        - calculate(expression: str): Evaluates a mathematical expression.

        User: What is 2 + 2?
        Thought: The user is asking a mathematical question. I should use the 'calculate' tool.
        Action:
        ```
        The agent's output for `Action` needs to match the tool-calling format (e.g., `tool_code("calculate", {"expression": "2+2"})`).

4.  **Error Handling and Reflection Prompts**:
    * Design prompts that guide the agent on how to react to errors or unexpected tool outputs.
    * "If the tool call fails, reflect on the error message and suggest a revised plan or a different tool."
    * "Observation: [Tool Output/Error Message]"
    * "Reflection: The previous tool call failed because... I will now try..."

5.  **Termination and Output Prompts**:
    * Clearly instruct the agent on *when* to stop and *how* to present its final answer.
    * "Once you have found the answer, output 'Final Answer:' followed by the complete response."


#### Additional best practices:

- [Best practices for prompt engineering with OpenAI API](https://help.openai.com/en/articles/6654000-best-practices-for-prompt-engineering-with-openai-api)
- [How to write good prompts](https://andymatuschak.org/prompts)

### Complete Guide to Prompt Engineering

- [A Complete Introduction to Prompt Engineering for Large Language Models](https://www.mihaileric.com/posts/a-complete-introduction-to-prompt-engineering)
- [Prompt Engineering Guide: How to Engineer the Perfect Prompts](https://richardbatt.co.uk/prompt-engineering-guide-how-to-engineer-the-perfect-prompts)

### Technical Aspects of Prompt Engineering

- [3 Principles for prompt engineering with GPT-3](https://www.linkedin.com/pulse/3-principles-prompt-engineering-gpt-3-ben-whately)
- [A Generic Framework for ChatGPT Prompt Engineering](https://medium.com/@thorbjoern.heise/a-generic-framework-for-chatgpt-prompt-engineering-7097f6513a0b)
- [Methods of prompt programming](https://generative.ink/posts/methods-of-prompt-programming)

### Resources for Prompt Engineering

- [Awesome ChatGPT Prompts](https://github.com/f/awesome-chatgpt-prompts)
- [Best 100+ Stable Diffusion Prompts](https://mpost.io/best-100-stable-diffusion-prompts-the-most-beautiful-ai-text-to-image-prompts)
- [DALLE Prompt Book](https://dallery.gallery/the-dalle-2-prompt-book)
- [OpenAI Cookbook](https://github.com/openai/openai-cookbook)
- [Prompt Engineering by Microsoft](https://microsoft.github.io/prompt-engineering)

## YouTube Videos

- [Advanced ChatGPT Prompt Engineering](https://www.youtube.com/watch?v=bBiTR_1sEmI)
- [ChatGPT: 5 Prompt Engineering Secrets For Beginners](https://www.youtube.com/watch?v=2zg3V66-Fzs)
- [Prompt Engineering - A new profession ?](https://www.youtube.com/watch?v=w102J3_9Bcs&ab_channel=PatrickDebois)
- [ChatGPT Guide: 10x Your Results with Better Prompts](https://www.youtube.com/watch?v=os-JX1ZQwIA)
- [Language Models and Prompt Engineering: Systematic Survey of Prompting Methods in NLP](https://youtube.com/watch?v=OsbUfL8w-mo&feature=shares)
- [Prompt Engineering 101: Autocomplete, Zero-shot, One-shot, and Few-shot prompting](https://youtube.com/watch?v=v2gD8BHOaX4&feature=shares)
