Sure! Here's a python script that demonstrates the concept of Random Forests using the famous Iris dataset.

```python
# Importing the required libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Loading the Iris dataset
iris = load_iris()
X = iris.data
y = iris.target

# Splitting the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Creating a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100)

# Training the classifier
rf_classifier.fit(X_train, y_train)

# Predicting on the test set
y_pred = rf_classifier.predict(X_test)

# Calculating accuracy
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
```

In this script, we import the necessary libraries, load the Iris dataset, and split it into training and testing sets. Then, we create a Random Forest classifier with 100 decision trees (`n_estimators=100`) and train it on the training set. Finally, we predict the target variable for the test set and calculate the accuracy of the classifier.

Note that you may need to install scikit-learn (`pip install scikit-learn`) if you don't have it already installed.