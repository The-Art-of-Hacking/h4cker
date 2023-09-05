Sure! Here's an example of a Python script that demonstrates the DBSCAN algorithm using the iris dataset from scikit-learn:

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn import datasets
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

# Load the iris dataset
iris = datasets.load_iris()
X = iris.data

# Scale the features
X = StandardScaler().fit_transform(X)

# Apply DBSCAN
dbscan = DBSCAN(eps=0.3, min_samples=5)
dbscan.fit(X)

# Get the predicted labels and number of clusters
labels = dbscan.labels_
n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
n_noise = list(labels).count(-1)

# Plot the results
unique_labels = set(labels)
colors = [plt.cm.Spectral(each)
          for each in np.linspace(0, 1, len(unique_labels))]

for k, col in zip(unique_labels, colors):
    if k == -1:
        # Black used for noise
        col = [0, 0, 0, 1]

    class_member_mask = (labels == k)

    xy = X[class_member_mask & core_samples_mask]
    plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
             markeredgecolor='k', markersize=6)

plt.title(f"Estimated number of clusters: {n_clusters}, Noise points: {n_noise}")
plt.show()
```

In this script, we first load the iris dataset and normalize the features using `StandardScaler`. Then we apply DBSCAN with `eps=0.3` (maximum distance between samples to form a cluster) and `min_samples=5` (minimum number of samples in a cluster).

Next, we retrieve the predicted labels and calculate the number of clusters and noise points. Finally, we plot the data points, highlighting the clusters and noise using different colors.

Note that you may need to have scikit-learn and matplotlib installed for this script to work.