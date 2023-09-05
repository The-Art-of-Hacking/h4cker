Sure! Here's a Python script that demonstrates the Monte Carlo Tree Search (MCTS) algorithm:

```python
import numpy as np
import random

class Node:
    def __init__(self, state, parent=None):
        self.state = state
        self.parent = parent
        self.children = []
        self.visits = 0
        self.rewards = 0

    def expand(self):
        possible_moves = self.state.get_possible_moves()
        for move in possible_moves:
            new_state = self.state.make_move(move)
            new_node = Node(new_state, parent=self)
            self.children.append(new_node)

    def select(self):
        selected_child = max(self.children, key=lambda child: child.get_ucb_score())
        return selected_child

    def simulate(self):
        current_state = self.state
        while not current_state.is_terminal():
            random_move = random.choice(current_state.get_possible_moves())
            current_state = current_state.make_move(random_move)
        return current_state.get_reward()

    def backpropagate(self, reward):
        self.visits += 1
        self.rewards += reward
        if self.parent:
            self.parent.backpropagate(reward)

    def get_ucb_score(self):
        exploration_factor = 1.414  # Adjust this for exploration vs exploitation trade-off
        exploitation_score = self.rewards / self.visits
        exploration_score = np.sqrt(np.log(self.parent.visits) / self.visits)
        return exploitation_score + exploration_factor * exploration_score


class State:
    def __init__(self):
        self.board = np.zeros((3, 3))
        self.current_player = 1

    def get_possible_moves(self):
        return [(i, j) for i in range(3) for j in range(3) if self.board[i][j] == 0]

    def make_move(self, move):
        new_state = State()
        new_state.board = np.copy(self.board)
        new_state.current_player = -self.current_player
        new_state.board[move[0]][move[1]] = self.current_player
        return new_state

    def is_terminal(self):
        return np.any(np.sum(self.board, axis=1) == 3) or np.any(np.sum(self.board, axis=0) == 3) \
                or np.trace(self.board) == 3 or np.trace(np.fliplr(self.board)) == 3 \
                or np.any(np.sum(self.board, axis=1) == -3) or np.any(np.sum(self.board, axis=0) == -3) \
                or np.trace(self.board) == -3 or np.trace(np.fliplr(self.board)) == -3 \
                or len(self.get_possible_moves()) == 0

    def get_reward(self):
        if np.any(np.sum(self.board, axis=1) == 3) or np.any(np.sum(self.board, axis=0) == 3) \
                or np.trace(self.board) == 3 or np.trace(np.fliplr(self.board)) == 3:
            return 1
        elif np.any(np.sum(self.board, axis=1) == -3) or np.any(np.sum(self.board, axis=0) == -3) \
                or np.trace(self.board) == -3 or np.trace(np.fliplr(self.board)) == -3:
            return -1
        else:
            return 0


def monte_carlo_tree_search(initial_state, iterations):
    root = Node(initial_state)

    for _ in range(iterations):
        # Selection
        selected_node = root
        while selected_node.children:
            selected_node = selected_node.select()

        # Expansion
        if not selected_node.state.is_terminal():
            selected_node.expand()
            selected_node = random.choice(selected_node.children)

        # Simulation
        reward = selected_node.simulate()

        # Backpropagation
        selected_node.backpropagate(reward)

    best_child = max(root.children, key=lambda child: child.visits)
    return best_child.state.board
    

# Test the Monte Carlo Tree Search algorithm on Tic-Tac-Toe game

initial_state = State()

best_move = monte_carlo_tree_search(initial_state, iterations=10000)

print("Best move found by Monte Carlo Tree Search:")
print(best_move)
```

In the above script, we define a `Node` class to represent each state in the game and a `State` class to maintain the current game state. The `monte_carlo_tree_search` function implements the MCTS algorithm and returns the best move found after the specified number of iterations.

In the Tic-Tac-Toe game example, each state is represented by a 3x3 game board. The `is_terminal` method checks if the game is over, and the `get_reward` method assigns rewards to terminal states (-1 for loss, 1 for win, 0 for draw). The `get_possible_moves` method returns all valid moves for the current state, and the `make_move` method creates a new state after making a move.

During each iteration of the MCTS algorithm, the `selection` step selects the most promising child node by applying the Upper Confidence Bound (UCB) formula. If the selected node is not terminal, the `expansion` step creates child nodes by simulating all possible moves. The `simulation` step randomly plays out the game from the selected child node until a terminal state is reached. Finally, the `backpropagation` step updates all nodes in the selected path with the simulation result. The process is repeated for the specified number of iterations.

After running the MCTS algorithm, the best move is determined by selecting the child node with the highest visit count from the root node. The resulting board configuration is returned as the best move.

Feel free to adjust the number of iterations and exploration factor to see different results.