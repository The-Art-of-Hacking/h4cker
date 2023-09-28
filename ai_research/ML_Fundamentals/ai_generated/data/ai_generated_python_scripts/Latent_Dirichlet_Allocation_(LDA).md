Sure! Here's an example Python script that demonstrates Latent Dirichlet Allocation (LDA) using the scikit-learn library:

```python
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation

# Sample data
documents = [
    'apple orange apple orange',
    'banana apple orange',
    'orange banana apple',
    'apple apple apple',
    'orange orange',
]

# Tokenize and vectorize the documents
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(documents)

# Apply LDA
lda_model = LatentDirichletAllocation(n_components=2, random_state=0)
lda_model.fit(X)

# Get the topics and their corresponding word probabilities
feature_names = vectorizer.get_feature_names_out()
topics = lda_model.components_

# Display the top words for each topic
for topic_idx, topic in enumerate(topics):
    top_words = [feature_names[i] for i in topic.argsort()[:-4:-1]]
    print(f"Top words for topic {topic_idx+1}: {', '.join(top_words)}")
```

In this script, we start by importing the necessary libraries: pandas for data manipulation, CountVectorizer for tokenization and vectorization of text documents, and LatentDirichletAllocation from sklearn.decomposition for performing LDA.

Next, we define a sample dataset of text documents. You can replace this with your own dataset.

We then use the CountVectorizer to transform the documents into a matrix representation with token counts. This matrix is then passed to the LatentDirichletAllocation model for training. In this example, we have specified `n_components=2` to indicate that we want to extract two topics.

After fitting the LDA model, we retrieve the feature names and the LDA model's components (topics and word probabilities).

Finally, we loop through each topic to display the top words with the highest probabilities for each topic.

Note that the results may vary each time you run the script due to the random nature of LDA.