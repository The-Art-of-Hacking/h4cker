Sure! The following is a python script that demonstrates the Naïve Bayes algorithm using the famous Iris dataset:

```python
import numpy as np
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score

# Load the Iris dataset
iris = load_iris()

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(iris.data, iris.target, test_size=0.2, random_state=42)

# Create an instance of the Naïve Bayes classifier
classifier = GaussianNB()

# Train the classifier using the training data
classifier.fit(X_train, y_train)

# Make predictions on the testing data
y_pred = classifier.predict(X_test)

# Calculate accuracy of the model
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
```

In this script, we start by importing the necessary libraries: `numpy` for numerical operations, `sklearn.datasets` to load the Iris dataset, `sklearn.model_selection` to split the data into training and testing sets, `sklearn.naive_bayes` for the Naïve Bayes classifier, and `sklearn.metrics` for calculating accuracy.

Next, we load the Iris dataset using `load_iris()` function. Then we split the data into training and testing sets using `train_test_split()` function, where `test_size=0.2` indicates that 20% of the data will be used for testing.

We create an instance of the Naïve Bayes classifier using `GaussianNB()`. This classifier assumes that features follow a Gaussian distribution. If your data doesn't meet this assumption, you can explore other variants like multinomial or Bernoulli Naïve Bayes.

We train the classifier using the training data by calling the `fit()` method and passing in the features (X_train) and corresponding labels (y_train).

Then, we make predictions on the testing data using the `predict()` method and passing in the features of the test set (X_test).

Finally, we calculate the accuracy of the classifier by comparing the predicted labels with the true labels from the testing set using the `accuracy_score()` function.

Hope this helps to demonstrate the Naïve Bayes algorithm in python!