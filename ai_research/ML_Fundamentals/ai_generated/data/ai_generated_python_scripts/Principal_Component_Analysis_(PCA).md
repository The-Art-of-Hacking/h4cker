Certainly! Here's a Python script that demonstrates Principal Component Analysis (PCA):

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

# Generate some random 2D data points
np.random.seed(0)
n_samples = 100
X = np.random.randn(n_samples, 2) * 2

# Apply PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)

# Plot the original data
plt.figure(figsize=(8, 4))
plt.subplot(1, 2, 1)
plt.scatter(X[:, 0], X[:, 1], alpha=0.5)
plt.title('Original Data')
plt.xlabel('X')
plt.ylabel('Y')

# Plot the PCA-transformed data
plt.subplot(1, 2, 2)
plt.scatter(X_pca[:, 0], X_pca[:, 1], alpha=0.5)
plt.title('PCA Transformed Data')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')

plt.tight_layout()
plt.show()
```

In this script, we generate a random 2D dataset using `np.random.randn()`. We then apply PCA using `sklearn.decomposition.PCA` and transform the data using `fit_transform()`. Finally, we visualize the original data and the PCA-transformed data in separate subplots using `matplotlib.pyplot.scatter()`.