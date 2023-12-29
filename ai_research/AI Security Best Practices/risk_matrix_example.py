# A Simple script to illustrate an example of a basic AI Risk Matrix

import matplotlib.pyplot as plt
import numpy as np

# Define the risks and their impact and likelihood
risks = {
    "Data Privacy Risk": {"Impact": "Medium", "Likelihood": "Medium"},
    "Diagnostic Accuracy Risk": {"Impact": "Very High", "Likelihood": "Low"},
    "Bias Risk": {"Impact": "High", "Likelihood": "Medium"}
}

# Mapping of impact and likelihood to numerical values
impact_mapping = {"Low": 1, "Medium": 2, "High": 3, "Very High": 4}
likelihood_mapping = {"Low": 1, "Medium": 2, "High": 3, "Very High": 4}

# Prepare data for plotting
x = [likelihood_mapping[risks[risk]['Likelihood']] for risk in risks]
y = [impact_mapping[risks[risk]['Impact']] for risk in risks]
labels = list(risks.keys())

# Create the plot
plt.figure(figsize=(8, 6))
plt.scatter(x, y, color='blue')
plt.title('AI System Risk Matrix', fontsize=18) 
plt.xlabel('Likelihood', fontsize=14)
plt.ylabel('Impact', fontsize=14)
plt.xticks([1, 2, 3, 4], ['Low', 'Medium', 'High', 'Very High'], fontsize=14)
plt.yticks([1, 2, 3, 4], ['Low', 'Medium', 'High', 'Very High'], fontsize=14)
plt.grid(True)

# Annotate the points with larger font
for i, label in enumerate(labels):
    plt.annotate(label, (x[i], y[i]), fontsize=14)

plt.show()
