Sure! Below is an example of a Python script demonstrating Gradient Boosting Machines (GBM) using the scikit-learn library:

```python
# Importing required libraries
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score

# Generate a random classification dataset
X, y = make_classification(n_samples=100, random_state=42)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create and fit the Gradient Boosting Classifier
gbm_model = GradientBoostingClassifier(random_state=42)
gbm_model.fit(X_train, y_train)

# Predict the labels for the test set
y_pred = gbm_model.predict(X_test)

# Calculate the accuracy score
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)
```

In this script, we first generate a random classification dataset using the `make_classification` function from scikit-learn. Then, we split the dataset into training and testing sets using the `train_test_split` function.

Next, we create an instance of the Gradient Boosting Classifier using `GradientBoostingClassifier` and fit the model to the training data using the `fit` method.

After fitting the model, we predict the labels for the test set using the `predict` method.

Finally, we calculate the accuracy score by comparing the predicted labels with the true labels and print it out.