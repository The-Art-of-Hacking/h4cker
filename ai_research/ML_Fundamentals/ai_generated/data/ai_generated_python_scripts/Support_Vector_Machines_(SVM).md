Sure! Here's an example script demonstrating the use of Support Vector Machines (SVM) for a binary classification problem using the famous iris dataset:

```python
# Importing the required libraries
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

# Loading the iris dataset
iris = datasets.load_iris()
X = iris.data
y = iris.target

# Splitting the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Creating the SVM classifier
svm = SVC(kernel='linear')

# Training the SVM classifier
svm.fit(X_train, y_train)

# Making predictions on the testing set
y_pred = svm.predict(X_test)

# Calculating the accuracy of the model
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")
```

In this script, the iris dataset is first loaded using the `datasets.load_iris()` method from the sklearn library. The features matrix `X` and the target vector `y` are then initialized. Next, the dataset is split into training and testing sets using `train_test_split()` function from the `model_selection` module.

A Support Vector Machine classifier is created using `SVC()` class from the `svm` module, with the `kernel` parameter set to 'linear'. The classifier is then trained on the training set using the `fit()` method.

Predictions are made on the testing set using the `predict()` method, and the accuracy of the model is calculated using the `accuracy_score()` function from the `metrics` module. Finally, the accuracy is printed to the console.

You can modify this script according to your specific use case or dataset. Remember to install the required packages (`scikit-learn`) in your Python environment before running the script.