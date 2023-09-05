Sure! Here's a Python script that demonstrates the t-SNE algorithm using the famous Iris dataset for visualization:

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn import datasets
from sklearn.manifold import TSNE

# Load the Iris dataset
iris = datasets.load_iris()
X = iris.data
y = iris.target

# Applying t-SNE
tsne = TSNE(n_components=2, random_state=42)
X_tsne = tsne.fit_transform(X)

# Plotting the t-SNE results
colors = ['r', 'g', 'b']
target_names = iris.target_names

plt.figure(figsize=(10, 6))
for i, target_name in enumerate(target_names):
    plt.scatter(X_tsne[y == i, 0], X_tsne[y == i, 1], c=colors[i], label=target_name)

plt.xlabel('First t-SNE Component')
plt.ylabel('Second t-SNE Component')
plt.title('t-SNE Visualization of Iris Dataset')
plt.legend()
plt.show()
```

In this script, we first import the necessary libraries (`numpy`, `matplotlib`, `sklearn.datasets`, and `sklearn.manifold.TSNE`) to perform the t-SNE algorithm. Then, we load the Iris dataset using the `datasets.load_iris()` from scikit-learn. The data and target variables are assigned to `X` and `y` arrays, respectively.

After that, we create an instance of the t-SNE algorithm with `TSNE(n_components=2, random_state=42)`. We choose 2 components (`n_components=2`) since we want to visualize the data in 2D. The `random_state` parameter is set to ensure reproducibility in the results. We then apply the t-SNE algorithm to the data using `fit_transform(X)`, which returns the transformed data as `X_tsne`.

Finally, we plot the t-SNE results using `matplotlib`. Each data point is plotted in a scatter plot, with different colors representing different classes ('setosa', 'versicolor', and 'virginica') in the Iris dataset.

To run this script, ensure that you have the necessary libraries installed (`numpy`, `matplotlib`, and `scikit-learn`). Save it as a .py file and execute it using a Python interpreter. The script will show a plot with the t-SNE visualization of the Iris dataset.