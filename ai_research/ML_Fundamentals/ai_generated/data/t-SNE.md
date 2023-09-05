# t-SNE: Dimentionality Reduction Technique

![t-SNE](https://scikit-learn.org/stable/_static/tsne_example.png)

t-SNE, which stands for t-Distributed Stochastic Neighbor Embedding, is a machine learning technique used for dimensionality reduction and visualization of high-dimensional data. It was introduced by Laurens van der Maaten and Geoffrey Hinton in 2008.

## Why t-SNE?

Dealing with high-dimensional data can be challenging as it becomes difficult to interpret and visualize the data effectively. Traditional visualization techniques like scatter plots fail to capture the complexity of high-dimensional data, which is where t-SNE comes to the rescue.

t-SNE helps in reducing the dimensionality of the data while preserving the local structures and relationships among the data points. It achieves this by constructing a probability distribution over pairs of high-dimensional data points and a similar distribution over pairs of low-dimensional points. It then minimizes the divergence between these two distributions using gradient descent, resulting in a low-dimensional representation of the data that can be easily visualized.

## How does it work?

The t-SNE algorithm consists of two main steps:

### Step 1: Constructing Similarity Measures
In this step, t-SNE constructs a similarity matrix that reflects the pairwise similarities between data points in the high-dimensional space. It does so using a Gaussian kernel to calculate the conditional probability of similarity between two points. The bandwidth of the kernel determines the scale at which similarities decay with increasing distance.

### Step 2: Dimensionality Reduction
Once the similarity matrix is constructed, t-SNE aims to find a low-dimensional representation of the data that best preserves the relationships depicted in the similarity matrix. It constructs a similar probability distribution in the low-dimensional space and minimizes the Kullback-Leibler divergence between the high-dimensional and low-dimensional distributions. This optimization is achieved using stochastic gradient descent.

## Advantages and Limitations

t-SNE has gained popularity due to its ability to effectively visualize high-dimensional data by preserving local structures. It often reveals hidden patterns, clusters, and outliers that might not be apparent in the original data.

However, it's important to be aware of some limitations of t-SNE. Firstly, t-SNE is non-linear, meaning that the distances in the reduced space may not correspond to the original distances accurately. Secondly, t-SNE can be highly sensitive to the parameters chosen, such as the perplexity, learning rate, and number of iterations. The perplexity determines the balance between preserving local and global structures, and it often requires experimentation to find the optimal value.

## Conclusion

t-SNE is a powerful technique for visualizing high-dimensional data and uncovering underlying structures. It has become an essential tool in various domains, including image recognition, natural language processing, bioinformatics, and more. By leveraging t-SNE, researchers and data scientists can gain valuable insights into their data, leading to better understanding and decision-making.