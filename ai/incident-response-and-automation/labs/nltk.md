# Lab Guide: Natural Language Processing with NLTK/Spacy

## Objective
To introduce students to the fundamental concepts of Natural Language Processing using NLTK and Spacy libraries.

## Prerequisites
- Basic understanding of Python programming.
- Knowledge of natural language processing basics.
- Python and necessary libraries installed: NLTK and Spacy.

### Setting Up the Environment:

Installing NLTK and Spacy:
```
pip install nltk spacy
```


## Steps

**Step 1**: Importing Necessary Libraries:
```python
import nltk
import spacy

# Load Spacy English Core
nlp = spacy.load('en_core_web_sm')
```

**Step 2**: Downloading Required NLTK Data Files and Spacy Language Models:
```python
nltk.download('punkt')
nltk.download('wordnet')
# For Spacy the model has already been loaded in Step 1.
```

**Step 3**: Text Tokenization:
```python
text = "Hello, this is an NLP lab session."

# NLTK Tokenization
sentences_nltk = nltk.sent_tokenize(text)
words_nltk = nltk.word_tokenize(text)
print(sentences_nltk, words_nltk)

# Spacy Tokenization
doc = nlp(text)
sentences_spacy = [sent.text for sent in doc.sents]
words_spacy = [token.text for token in doc]
print(sentences_spacy, words_spacy)
```

**Step 4**: Stemming and Lemmatization:
```python
from nltk.stem import PorterStemmer, WordNetLemmatizer

# NLTK Stemming and Lemmatization
stemmer = PorterStemmer()
lemmatizer = WordNetLemmatizer()
word = "running"
print(stemmer.stem(word))
print(lemmatizer.lemmatize(word))

# Spacy Lemmatization
doc = nlp(word)
print(doc[0].lemma_)
```

**Step 5**: Part-of-Speech (POS) Tagging:
```python
# NLTK POS Tagging
words = nltk.word_tokenize(text)
pos_tags_nltk = nltk.pos_tag(words)
print(pos_tags_nltk)

# Spacy POS Tagging
doc = nlp(text)
pos_tags_spacy = [(token.text, token.pos_) for token in doc]
print(pos_tags_spacy)
```

**Step 6**: Named Entity Recognition (NER):
```python
# Spacy NER
text = "Barack Obama was the 44th president of the United States."
doc = nlp(text)
for ent in doc.ents:
    print(ent.text, ent.label_)
```

**Step 7**: Sentiment Analysis:
```python
# Here we demonstrate sentiment analysis using Spacy with a pretrained model (You might need to install it separately)
text = "The movie was absolutely fantastic!"
doc = nlp(text)
print(doc._.sentiment)
```

**Step 8**: Text Similarity and Clustering:
```python
# Text Similarity using Spacy
doc1 = nlp("This is a sentence.")
doc2 = nlp("This is another sentence.")
print(doc1.similarity(doc2))

# Text Clustering would generally be a more involved process, which may not fit here. However, students can be introduced to concepts and techniques related to text clustering at this step.
```

**Step 9**: Text Summarization:
```python
# Simple Text Summarization (extractive summarization using sentence similarity)
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np

sentences = ["This is sentence 1", "This is sentence 2", "This is sentence 3"]
vectorizer = CountVectorizer().fit_transform(sentences)
vectors = vectorizer.toarray()
csim = cosine_similarity(vectors)
print(csim)
# Use the similarity matrix to extract most relevant sentences (simple extractive summarization)
```

**Step 10**: Information Retrieval:
```python
# Simple Information Retrieval (using keyword matching)
documents = ["doc1: This is a document about AI.", "doc2: This is a document about ML.", "doc3: This document is about NLP."]
query = "NLP"
relevant_docs = [doc for doc in documents if query in doc]
print(relevant_docs)
```

**Step 11**: Assigning Project:
```python
# No code required. Assign a project to students based on what they learned in the lab.
```

These code snippets are examples that demonstrate how to perform each task using Python with NLTK and Spacy. They are quite basic and meant to serve as an introduction to NLP tasks. 
