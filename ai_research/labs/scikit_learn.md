# Machine Learning Basics with Scikit-learn

#### **Objective**

To introduce students to the fundamental concepts and techniques of machine learning using the Scikit-learn library.

#### **Prerequisites**
For convenience you can use the terminal window at the OReilly interactive lab: https://learning.oreilly.com/scenarios/ethical-hacking-advanced/9780137673469X002/

1. Basic understanding of Python programming.
2. Familiarity with data manipulation libraries like Pandas and NumPy.
3. Python and necessary libraries installed: Scikit-learn, Pandas, and NumPy.

#### **Lab Outline**

1. **Introduction to Machine Learning**:
    - Brief explanation of machine learning and its types (Supervised, Unsupervised).
    - Introduction to Scikit-learn library.

2. **Setting Up the Environment**:
    - Installing Scikit-learn, Pandas, and NumPy:
      ```bash
      pip3 install scikit-learn pandas numpy
      ```

3. **Data Preprocessing**:

   - **Step 1**: Importing Necessary Libraries:
     ```python
     import numpy as np
     import pandas as pd
     from sklearn import datasets
     ```
     
   - **Step 2**: Loading a Dataset:
     ```python
     iris = datasets.load_iris()
     X, y = iris.data, iris.target
     ```

   - **Step 3**: Handling Missing Values (if any):
     ```python
     # Using SimpleImputer to fill missing values
     from sklearn.impute import SimpleImputer
     imputer = SimpleImputer(strategy="mean")
     X_imputed = imputer.fit_transform(X)
     ```

   - **Step 4**: Splitting the Dataset into Training and Testing Sets:
     ```python
     from sklearn.model_selection import train_test_split
     X_train, X_test, y_train, y_test = train_test_split(X_imputed, y, test_size=0.2, random_state=42)
     ```

4. **Building Machine Learning Models**:

   - **Step 5**: Training a Decision Tree Model:
     ```python
     from sklearn.tree import DecisionTreeClassifier
     dt_classifier = DecisionTreeClassifier(random_state=42)
     dt_classifier.fit(X_train, y_train)
     ```

   - **Step 6**: Training a Logistic Regression Model:
     ```python
     from sklearn.linear_model import LogisticRegression
     lr_classifier = LogisticRegression(random_state=42)
     lr_classifier.fit(X_train, y_train)
     ```

5. **Evaluating Models**:

   - **Step 7**: Making Predictions and Evaluating Models:
     ```python
     from sklearn.metrics import accuracy_score

     # For Decision Tree
     y_pred_dt = dt_classifier.predict(X_test)
     dt_accuracy = accuracy_score(y_test, y_pred_dt)

     # For Logistic Regression
     y_pred_lr = lr_classifier.predict(X_test)
     lr_accuracy = accuracy_score(y_test, y_pred_lr)

     print(f"Decision Tree Accuracy: {dt_accuracy}")
     print(f"Logistic Regression Accuracy: {lr_accuracy}")
     ```

6. **Hyperparameter Tuning and Cross-Validation**:

   - **Step 8**: Implementing Grid Search Cross-Validation:
     ```python
     from sklearn.model_selection import GridSearchCV

     # For Decision Tree
     param_grid_dt = {'max_depth': [3, 5, 7], 'min_samples_split': [2, 5, 10]}
     grid_search_dt = GridSearchCV(dt_classifier, param_grid_dt, cv=3)
     grid_search_dt.fit(X_train, y_train)
     
     # Best parameters and score for Decision Tree
     print(grid_search_dt.best_params_)
     print(grid_search_dt.best_score_)
     ```

7. **Conclusion and Further Exploration**:
   - Discuss the results and explore how to further improve the models.
   - Introduce more advanced machine learning techniques and algorithms.

8. **Assignment/Project**:
   - Assign a project where students have to apply the techniques learned in the lab to a real-world dataset and build a predictive model.

#### **Assessment**

- **Lab Participation**: Active participation in lab exercises.
- **Quiz**: Conduct a short quiz to assess the understanding of students regarding the concepts taught in the lab.
- **Project Evaluation**: Evaluate the project based on the application of concepts, the accuracy of the model, and the presentation of results.

#### **Resources**

1. Scikit-learn [documentation](https://scikit-learn.org/stable/documentation.html) for detailed guidance on using the library.
2. Online courses and tutorials to further explore machine learning concepts.

By the end of this lab, students should be able to understand and implement basic machine learning concepts using the Scikit-learn library. They should also be capable of building and evaluating simple machine learning models.
