# Supervised, Unsupervised, and Reinforcement Learning


| Aspect                      | Supervised Learning                        | Unsupervised Learning                      | Reinforcement Learning                    |
|-----------------------------|--------------------------------------------|--------------------------------------------|-------------------------------------------|
| Definition                  | A type of learning where the model is trained on a labeled dataset, which means that the training data includes both input data and the corresponding correct outputs. | Learning from an unlabeled dataset, the model tries to find the underlying patterns and structures in the data. | A type of learning where the model learns to interact with an environment to achieve a goal or maximize some notion of cumulative reward. |
| Training Data               | Labeled data (features and labels)         | Unlabeled data (features only)             | Interaction with the environment, rewards based on actions. |
| Goal                        | To make accurate predictions or classifications based on the input data. | To find hidden patterns or groupings in the data. | To find a strategy to obtain the maximum cumulative reward over time. |
| Algorithms                  | Decision Trees, Support Vector Machines, Neural Networks, etc. | Clustering (e.g., K-means), Association (e.g., Apriori), Principal Component Analysis, etc. | Q-learning, Deep Q Network (DQN), Policy Gradients, etc. |
| Real-world Applications     | Image recognition, Spam detection, Credit risk analysis, etc. | Market segmentation, Anomaly detection, Recommender systems, etc. | Autonomous vehicles, Game playing (like AlphaGo), Robotics, etc. |
| Evaluation Metrics          | Accuracy, Precision, Recall, F1-score, etc.| Silhouette score, Davies-Bouldin index, etc. | Reward function, which may vary greatly depending on the specific task. |


## Common Algorithms

| Supervised Learning                        | Unsupervised Learning                      | Reinforcement Learning                   |
|--------------------------------------------|--------------------------------------------|------------------------------------------|
| Linear Regression                          | K-Means Clustering                         | Q-Learning                               |
| Logistic Regression                        | Hierarchical Clustering                    | Deep Q-Network (DQN)                     |
| Decision Trees                             | DBSCAN                                     | Policy Gradients                         |
| Support Vector Machines (SVM)              | Gaussian Mixture Models (GMM)              | Actor-Critic Methods                     |
| Neural Networks                            | Principal Component Analysis (PCA)         | Proximal Policy Optimization (PPO)       |
| Naïve Bayes                                | Independent Component Analysis (ICA)       | Monte Carlo Tree Search (MCTS)           |
| k-Nearest Neighbors (k-NN)                 | t-SNE                                      | SARSA                                    |
| Gradient Boosting Machines (GBM)           | Latent Dirichlet Allocation (LDA)         | Temporal Difference Learning (TD Learning)|
| Random Forests                             | Association Rules (Apriori, FP-Growth)    | Trust Region Policy Optimization (TRPO)  |
