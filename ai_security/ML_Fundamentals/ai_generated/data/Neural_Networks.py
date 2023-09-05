import numpy as np
import matplotlib.pyplot as plt

# Create a simple neural network with one input layer, one hidden layer, and one output layer
class NeuralNetwork:
    def __init__(self):
        self.weights1 = np.random.rand(3, 4)  # weight matrix between input and hidden layer
        self.weights2 = np.random.rand(4, 1)  # weight matrix between hidden and output layer
        self.bias1 = np.random.rand(1, 4)      # bias matrix for hidden layer
        self.bias2 = np.random.rand(1, 1)      # bias matrix for output layer

    def sigmoid(self, x):
        # Sigmoid activation function
        return 1 / (1 + np.exp(-x))

    def forward_propagation(self, X):
        # Perform forward propagation
        self.hidden_layer = self.sigmoid(np.dot(X, self.weights1) + self.bias1)  # calculate hidden layer activations
        self.output_layer = self.sigmoid(np.dot(self.hidden_layer, self.weights2) + self.bias2)  # calculate output layer activations
        return self.output_layer

    def backward_propagation(self, X, y, output):
        # Perform backward propagation to update weights and biases
        self.error = y - output  # calculate error
        self.delta_output = self.error * (output * (1 - output))  # calculate output gradient
        self.delta_hidden = np.dot(self.delta_output, self.weights2.T) * (self.hidden_layer * (1 - self.hidden_layer))  # calculate hidden gradient
        self.weights2 += np.dot(self.hidden_layer.T, self.delta_output)  # update weights between hidden and output layer
        self.weights1 += np.dot(X.T, self.delta_hidden)  # update weights between input and hidden layer
        self.bias2 += np.sum(self.delta_output, axis=0)  # update bias for output layer
        self.bias1 += np.sum(self.delta_hidden, axis=0)  # update bias for hidden layer

    def train(self, X, y, epochs):
        # Train the neural network
        for _ in range(epochs):
            output = self.forward_propagation(X)
            self.backward_propagation(X, y, output)

    def predict(self, X):
        # Make predictions
        return self.forward_propagation(X)

# Create a sample dataset for XOR gate
X = np.array([[0, 0], [0, 1], [1, 0], [1, 1]])
y = np.array([[0], [1], [1], [0]])

# Create and train the neural network
nn = NeuralNetwork()
nn.train(X, y, epochs=10000)

# Make predictions on the same dataset
predictions = nn.predict(X)

# Print the predictions
print("Predictions:")
for i in range(len(predictions)):
    print(f"Input: {X[i]}, Predicted Output: {predictions[i]}")

# Plot the predictions
plt.scatter(X[:, 0], X[:, 1], c=predictions.flatten(), cmap='viridis')
plt.xlabel("Input 1")
plt.ylabel("Input 2")
plt.title("Neural Network Predictions for XOR Gate")
plt.show()