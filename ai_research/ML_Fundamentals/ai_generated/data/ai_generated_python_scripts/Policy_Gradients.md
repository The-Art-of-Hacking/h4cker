Sure! Here's an example of a Python script that demonstrates the concept of Policy Gradients using the OpenAI Gym environment and a simple neural network:

```python
import gym
import numpy as np
from keras.models import Sequential
from keras.layers import Dense

# Create the policy network
def build_policy_network(input_shape, output_units):
    model = Sequential()
    model.add(Dense(24, activation='relu', input_shape=input_shape))
    model.add(Dense(24, activation='relu'))
    model.add(Dense(output_units, activation='softmax'))
    model.compile(optimizer='adam', loss='categorical_crossentropy')
    return model

def choose_action(state, model):
    state = np.reshape(state, [1, input_shape[0]])
    prob_dist = model.predict(state).flatten()
    action = np.random.choice(num_actions, 1, p=prob_dist)[0]
    return action

def discount_rewards(rewards, gamma):
    discounted_rewards = np.zeros_like(rewards)
    running_sum = 0
    for t in reversed(range(len(rewards))):
        running_sum = running_sum * gamma + rewards[t]
        discounted_rewards[t] = running_sum
    return discounted_rewards

# Set hyperparameters
learning_rate = 0.01
num_episodes = 1000
gamma = 0.99

# Create the environment
env = gym.make('CartPole-v0')
input_shape = env.observation_space.shape
num_actions = env.action_space.n

# Build the policy network and initialize weights
policy_network = build_policy_network(input_shape, num_actions)

# Start training
for episode in range(num_episodes):
    state = env.reset()
    done = False
    episode_rewards = []
    episode_gradients = []
    
    while not done:
        # Choose action based on the policy network
        action = choose_action(state, policy_network)
        
        # Take the chosen action and observe the next state and reward
        next_state, reward, done, _ = env.step(action)
        
        # Store the reward
        episode_rewards.append(reward)
        
        # Compute the one-hot encoded action
        action_onehot = np.zeros(num_actions)
        action_onehot[action] = 1
        
        # Compute the gradient of the policy network's output w.r.t. the action taken
        with tf.GradientTape() as tape:
            logits = policy_network.predict(np.expand_dims(state, axis=0))
            loss = tf.reduce_sum(tf.multiply(logits, tf.convert_to_tensor(action_onehot, dtype=tf.float32)))
        
        # Store the gradients
        episode_gradients.append(tape.gradient(loss, policy_network.trainable_variables))
        
        state = next_state
    
    # Update the policy network
    rewards = discount_rewards(episode_rewards, gamma)
    for i in range(len(episode_gradients)):
        grads = episode_gradients[i]
        for j in range(len(grads)):
            policy_network.trainable_variables[j].assign_sub(learning_rate * grads[j] * rewards[i])
    
    if episode % 100 == 0:
        print("Episode {}: Average reward = {}".format(episode, np.mean(episode_rewards)))
```

This script uses the `gym` package to create the CartPole-v0 environment, which is a classic reinforcement learning problem. It then builds a simple neural network as the policy network, with two hidden layers and a softmax output layer for the action probabilities. It implements the `choose_action` function to sample actions based on the probabilities predicted by the policy network.

During training, the script collects rewards and gradients for each episode. It then applies the policy gradient update rule, computing the discounted rewards and updating the policy network weights accordingly. Finally, it prints the average reward for every 100 episodes.

Note that this script is a simplified example and may not converge to the optimal policy. Policy Gradients typically require careful tuning of hyperparameters, selecting suitable network architectures, and using more advanced techniques like baseline estimation and advantage normalization to improve the training stability and performance.