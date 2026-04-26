# Introduction to LLMs and SLMs
Large Language Models (LLMs) have become super hot in the rapidly evolving field of artificial intelligence. This section compares LLMs and 

## Intro to LLMs
LLMs are a type of artificial intelligence (AI) model that uses deep learning techniques. The most prevelant examples are transformer architectures. They are trained to recognize patterns in language, allowing them to predict and generate text that is coherent and contextually relevant. This capability distinguishes them from traditional machine learning models, which typically handle structured data like numerical or tabular information.

### Applications and Impact
- Conversational AI: LLMs are integral to developing conversational systems that interact with humans naturally. They enhance natural language understanding (NLU) and generation (NLG), enabling more intuitive and context-aware interactions.
- Information Retrieval and Text Analysis: LLMs can efficiently sift through large volumes of text to extract relevant information, summarize content, and perform complex analysis.
- Creative and Content Generation: These models can produce creative content, such as stories, articles, images, audio, etc. Combining text with audiovisual data could enable LLMs to understand and generate content across multiple formats, broadening their applicability

## Transformer Architecture
Transformers use self-attention to weigh the significance of different words in a sentence relative to each other. This mechanism allows the model to focus on relevant parts of the input sequence, enabling it to capture long-range dependencies and contextual information more effectively than previous models like recurrent neural networks (RNNs) and convolutional neural networks (CNNs).
Unlike RNNs, which process data sequentially, transformers can process input sequences in parallel. 

The [paper "Attention Is All You Need"](https://arxiv.org/pdf/1706.03762) introduces the concept of transformer models which are the types of AI models that fuel ChatGPT, Claude, Mistral, Llama, and thousands of other models that you can find in [HuggingFace](https://huggingface.co/models).

## LLMs vs SLMs
LLMs are super popular after the introduction of ChatGPT years ago. However, Small Language Models (SLMs) are also becoming very popular. 
Due to their size, LLMs require substantial computational resources for training and inference, often involving specialized hardware like GPUs or TPUs. This makes them costly to deploy and maintain. SLMs have lower computational requirements and can be run on local machines with less powerful hardware. This makes them more accessible and cost-effective for smaller organizations or specific applications.

SLMs are often used for targeted domain specific applications.

Examples of SLMs include:

- [LLaMA 3 by Meta](https://llama.meta.com/)
- [Phi 3 by Microsoft](https://azure.microsoft.com/en-us/products/phi-3)
- [Mixtral 8x7B by Mistral AI](https://mistral.ai/news/mixtral-of-experts/)
- [Gemma by Google](https://ai.google.dev/gemma)
- [OpenELM Family by Apple](https://machinelearning.apple.com/research/openelm)
- [REPCNN by Apple](https://machinelearning.apple.com/research/repcnn-micro)
