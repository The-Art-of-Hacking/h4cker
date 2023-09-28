Sure! Here's a simple example of a Python script that demonstrates Temporal Difference Learning (TD Learning) using a simple grid world environment:

```python
import numpy as np

# Environment
grid_size = 4
num_episodes = 100
start_state = (0, 0)
end_state = (grid_size - 1, grid_size - 1)
actions = ['up', 'down', 'left', 'right']

# Hyperparameters
alpha = 0.1  # learning rate
gamma = 0.9  # discount factor

# Initialize state-action value function
Q = np.zeros((grid_size, grid_size, len(actions)))

# Helper function to choose an action based on Q-values (epsilon-greedy policy)
def choose_action(state, epsilon):
    if np.random.random() < epsilon:
        return np.random.choice(actions)
    return actions[np.argmax(Q[state])]

# Helper function to get the next state and reward based on the chosen action
def get_next_state_reward(state, action):
    if action == 'up':
        next_state = (state[0] - 1, state[1])
    elif action == 'down':
        next_state = (state[0] + 1, state[1])
    elif action == 'left':
        next_state = (state[0], state[1] - 1)
    elif action == 'right':
        next_state = (state[0], state[1] + 1)
    
    if next_state[0] < 0 or next_state[0] >= grid_size or next_state[1] < 0 or next_state[1] >= grid_size:
        # Hit wall, stay in the same state with a negative reward
        return state, -10
    elif next_state == end_state:
        # Reached the end, stay in the same state with a positive reward
        return state, 10
    else:
        return next_state, 0  # Regular move, stay in the same state with no reward
    

# TD Learning algorithm
for episode in range(num_episodes):
    state = start_state
    epsilon = 1.0 / (episode + 1)  # epsilon-greedy exploration rate
    
    while state != end_state:
        action = choose_action(state, epsilon)
        next_state, reward = get_next_state_reward(state, action)
        
        # Update Q-values using Temporal Difference Learning
        Q[state][actions.index(action)] += alpha * (reward + gamma * np.max(Q[next_state]) - Q[state][actions.index(action)])
        
        state = next_state

# Print the learned Q-values
print(Q)
```

In this script, we define a simple grid world environment with a start state, an end state, and possible actions ('up', 'down', 'left', 'right'). The script then uses the Temporal Difference Learning algorithm to update the state-action values in the Q-table based on the rewards obtained from interactions with the environment. Finally, it prints the learned Q-values.