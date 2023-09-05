Sure! Below is an example script that demonstrates the SARSA (State-Action-Reward-State-Action) algorithm using a simple grid world environment:

```python
import numpy as np

# Define the grid world environment
grid = [
    [0, 0, 0, 0],
    [0, -1, 0, -1],
    [0, 0, 0, -1],
    [0, -1, 0, 1]
]

# Initialize Q-table
Q = np.zeros((4, 4, 4))  # Q(s, a) - 4x4 grid, 4 actions (up, down, left, right)

# Define epsilon-greedy exploration
epsilon = 0.1

# Define learning parameters
alpha = 0.1  # Learning rate
gamma = 0.9  # Discount factor

# Define action mapping
actions = ['up', 'down', 'left', 'right']

# Get next action using epsilon-greedy exploration
def get_action(state):
    if np.random.rand() < epsilon:
        action = np.random.choice(actions)
    else:
        action = actions[np.argmax(Q[state[0], state[1]])]
    return action

# Update Q-values using SARSA algorithm
def update_q_values(state, action, reward, next_state, next_action):
    Q[state[0], state[1], actions.index(action)] += alpha * (
            reward + gamma * Q[next_state[0], next_state[1], actions.index(next_action)] -
            Q[state[0], state[1], actions.index(action)])

# Train the agent
def train_agent():
    num_episodes = 1000
    
    for episode in range(num_episodes):
        state = [3, 0]  # Start state
        action = get_action(state)
        
        while True:
            # Perform selected action
            if action == 'up':
                next_state = [state[0] - 1, state[1]]
            elif action == 'down':
                next_state = [state[0] + 1, state[1]]
            elif action == 'left':
                next_state = [state[0], state[1] - 1]
            else:
                next_state = [state[0], state[1] + 1]
            
            # Check if next state is valid
            if next_state[0] < 0 or next_state[0] >= 4 or next_state[1] < 0 or next_state[1] >= 4:
                next_state = state
            
            # Get next action using epsilon-greedy exploration
            next_action = get_action(next_state)
            
            # Update Q-values
            update_q_values(state, action, grid[next_state[0]][next_state[1]], next_state, next_action)
            
            # Update current state and action
            state = next_state
            action = next_action
            
            # Break if goal state reached
            if grid[state[0]][state[1]] == 1:
                break

# Test the trained agent
def test_agent():
    state = [3, 0]  # Start state
    
    while True:
        # Choose the best action based on Q-values
        action = actions[np.argmax(Q[state[0], state[1]])]
        
        # Perform selected action
        if action == 'up':
            next_state = [state[0] - 1, state[1]]
        elif action == 'down':
            next_state = [state[0] + 1, state[1]]
        elif action == 'left':
            next_state = [state[0], state[1] - 1]
        else:
            next_state = [state[0], state[1] + 1]
        
        # Print the current state and action taken
        print(f"Current state: {state}, Action: {action}")
        
        # Update current state
        state = next_state
        
        # Break if goal state reached
        if grid[state[0]][state[1]] == 1:
            print("Reached the goal!")
            break

# Train and test the agent
train_agent()
test_agent()
```

This script demonstrates SARSA algorithm in a simple grid world environment, where the agent has to navigate from the starting state `[3, 0]` to the goal state `[3, 3]` while avoiding obstacles represented by `-1`. The agent uses the SARSA algorithm to learn optimal Q-values and then applies them to reach the goal state.