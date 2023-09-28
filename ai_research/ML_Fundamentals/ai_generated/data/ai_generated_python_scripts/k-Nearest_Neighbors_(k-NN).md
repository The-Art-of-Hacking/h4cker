Sure! Here's an example of a Python script that demonstrates the k-Nearest Neighbors (k-NN) algorithm using the scikit-learn library:

```python
import numpy as np
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score

# Load the Iris dataset
iris = load_iris()
X = iris.data
y = iris.target

# Split the dataset into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create a k-NN classifier with k = 3
k = 3
knn = KNeighborsClassifier(n_neighbors=k)

# Fit the classifier to the training data
knn.fit(X_train, y_train)

# Predict the classes for the test set
y_pred = knn.predict(X_test)

# Calculate the accuracy of the classifier
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")

# Example usage: Predict the class for new data
new_data = np.array([[5.0, 3.6, 1.4, 0.2]])
predicted_class = knn.predict(new_data)
print(f"Predicted class: {predicted_class}")
```

In this script, we first load the famous Iris dataset using the scikit-learn `load_iris` function. Then, we split the dataset into training and test sets using the `train_test_split` function, with 80% for training and 20% for testing.

Next, we create a k-NN classifier with `k = 3` using the `KNeighborsClassifier` class from scikit-learn. We fit the classifier to the training data using the `fit` method.

After that, we predict the classes for the test set using the `predict` method. We calculate the accuracy of the classifier by comparing the predicted classes with the true classes using the `accuracy_score` function.

Finally, we demonstrate the usage of the trained classifier by predicting the class for a new data point with the `predict` method.

Note that this is a basic example to showcase the concept of k-NN. In practice, you would need to perform more extensive data preprocessing, feature scaling, hyperparameter tuning, and evaluation to build a more robust and accurate model.