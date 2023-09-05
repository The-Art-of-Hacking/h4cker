Sure! Below is a Python script that demonstrates the concept of Decision Trees using the popular scikit-learn library.

```python
# Import necessary libraries
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics

# Load the Iris dataset
data = load_iris()
X = data.data
y = data.target

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create a Decision Tree classifier
clf = DecisionTreeClassifier()

# Train the classifier on the training data
clf.fit(X_train, y_train)

# Make predictions on the testing data
y_pred = clf.predict(X_test)

# Evaluate the model
accuracy = metrics.accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

# Visualize the Decision Tree
from sklearn import tree
import matplotlib.pyplot as plt

plt.figure(figsize=(12, 8))
tree.plot_tree(clf, feature_names=data.feature_names, class_names=data.target_names, filled=True)
plt.show()
```

In this script, we first import the necessary libraries: `load_iris` from `sklearn.datasets` to load the Iris dataset, `train_test_split` from `sklearn.model_selection` to split the dataset into training and testing sets, `DecisionTreeClassifier` from `sklearn.tree` to create the Decision Tree classifier, and `metrics` from `sklearn` to evaluate the model.

We load the Iris dataset and split it into training and testing sets using a 80:20 split. Then, we create a Decision Tree classifier and train it on the training data. After that, we make predictions on the testing data and evaluate the model using accuracy as the metric.

Finally, we visualize the Decision Tree using `tree.plot_tree` from `sklearn` and `matplotlib.pyplot`. The resulting tree is displayed using a figure.