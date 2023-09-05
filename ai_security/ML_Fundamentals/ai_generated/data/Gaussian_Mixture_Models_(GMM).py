Sure! Here's a Python script that demonstrates the concept of Gaussian Mixture Models (GMM) using the scikit-learn library:

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn.mixture import GaussianMixture

# Generate random data
np.random.seed(0)
n_samples = 1000
n_components = 3
X = np.concatenate([
    np.random.multivariate_normal([0, 0], [[1, 0], [0, 20]], int(0.1 * n_samples)),
    np.random.multivariate_normal([-5, 0], [[1, 0], [0, 1]], int(0.3 * n_samples)),
    np.random.multivariate_normal([5, 10], [[4, 0], [0, 4]], int(0.6 * n_samples))
])

# Fit the GMM model
gmm = GaussianMixture(n_components=n_components)
gmm.fit(X)

# Predict the labels for the data samples
y_pred = gmm.predict(X)

# Visualize the results
plt.scatter(X[:, 0], X[:, 1], c=y_pred, cmap='viridis')
plt.xlabel('X')
plt.ylabel('Y')
plt.title('Gaussian Mixture Models')
plt.show()
```

In this script, we first generate random data points from three different Gaussian distributions. We then use the `GaussianMixture` class from scikit-learn to fit a GMM model on this data. Next, we use the learned GMM model to predict the labels for each data sample. Finally, we visualize the results by plotting the data points colored according to their predicted labels.

Please make sure you have the scikit-learn and matplotlib libraries installed in your Python environment before running this script.