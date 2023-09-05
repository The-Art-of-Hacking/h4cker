Sure! Here's a Python script that demonstrates Independent Component Analysis (ICA) using the scikit-learn library:

```python
import numpy as np
from sklearn.decomposition import FastICA
import matplotlib.pyplot as plt

# Generate data
np.random.seed(0)
n_samples = 2000
time = np.linspace(0, 8, n_samples)

s1 = np.sin(2 * time)  # Signal 1: sinusoidal signal
s2 = np.sign(np.sin(3 * time))  # Signal 2: square signal

S = np.c_[s1, s2]
S += 0.2 * np.random.normal(size=S.shape)  # Add noise

# Mix data
A = np.array([[1, 1], [0.5, 2]])  # Mixing matrix
X = np.dot(S, A.T)  # Generate observations

# ICA
ica = FastICA(n_components=2)
S_ = ica.fit_transform(X)  # Reconstruct signals
A_ = ica.mixing_  # Estimated mixing matrix

# Plot results
plt.figure(figsize=(8, 6))

models = [X, S, S_]
names = ['Observations (mixed signals)',
         'True Sources',
         'ICA estimated sources']

colors = ['red', 'steelblue']

for i, (model, name) in enumerate(zip(models, names), 1):
    plt.subplot(3, 1, i)
    plt.title(name)
    for sig, color in zip(model.T, colors):
        plt.plot(sig, color=color)

plt.tight_layout()
plt.show()
```

This script demonstrates ICA by generating two mixed signals, `s1` and `s2`, adding noise, and then applying ICA to separate the original signals. The original signals are represented by the `S` matrix, and the observed mixed signals are stored in the `X` matrix. The `FastICA` class from scikit-learn is used to perform ICA.

The script plots three subplots: the observed mixed signals, the true sources, and the estimated sources achieved through ICA.

Make sure to install required dependencies (scikit-learn, numpy, matplotlib) before running the script.