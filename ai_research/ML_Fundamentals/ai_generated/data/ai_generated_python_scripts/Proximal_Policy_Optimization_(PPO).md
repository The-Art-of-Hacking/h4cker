Sure! Here's a Python script that demonstrates Proximal Policy Optimization (PPO) using the OpenAI Gym's CartPole environment:

```python
import gym
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Set up the CartPole environment
env = gym.make("CartPole-v1")
num_states = env.observation_space.shape[0]
num_actions = env.action_space.n

# PPO Agent
class PPOAgent:
    def __init__(self, num_states, num_actions):
        self.gamma = 0.99  # Discount factor
        self.epsilon = 0.2  # Clipping factor
        self.actor_lr = 0.0003  # Actor learning rate
        self.critic_lr = 0.001  # Critic learning rate

        self.actor = self.build_actor()
        self.critic = self.build_critic()

    def build_actor(self):
        inputs = layers.Input(shape=(num_states,))
        hidden = layers.Dense(128, activation="relu")(inputs)
        action_probs = layers.Dense(num_actions, activation="softmax")(hidden)

        model = keras.Model(inputs=inputs, outputs=action_probs)
        optimizer = tf.keras.optimizers.Adam(learning_rate=self.actor_lr)
        model.compile(optimizer=optimizer, loss="categorical_crossentropy")
        return model

    def build_critic(self):
        inputs = layers.Input(shape=(num_states,))
        hidden = layers.Dense(128, activation="relu")(inputs)
        value = layers.Dense(1, activation="linear")(hidden)

        model = keras.Model(inputs=inputs, outputs=value)
        optimizer = tf.keras.optimizers.Adam(learning_rate=self.critic_lr)
        model.compile(optimizer=optimizer, loss="mean_squared_error")
        return model

    def choose_action(self, state):
        state = np.expand_dims(state, axis=0)
        action_probs = self.actor.predict(state).flatten()

        # Sample an action from the action probability distribution
        action = np.random.choice(num_actions, 1, p=action_probs)[0]
        return action

    def compute_returns(self, rewards, dones, values):
        returns = np.zeros_like(rewards)
        discounted_sum = 0
        for i in reversed(range(len(rewards))):
            if dones[i]:
                discounted_sum = 0
            discounted_sum = rewards[i] + self.gamma * discounted_sum
            returns[i] = discounted_sum

        advantages = returns - values
        advantages = (advantages - np.mean(advantages)) / (np.std(advantages) + 1e-10)
        return returns, advantages

    def train(self, old_states, actions, rewards, dones, values):
        returns, advantages = self.compute_returns(rewards, dones, values)

        # Convert inputs to numpy arrays for better indexing
        old_states = np.array(old_states)
        actions = np.array(actions)
        returns = np.array(returns)
        advantages = np.array(advantages)

        num_samples = len(old_states)

        # Actor training
        actions_one_hot = np.eye(num_actions)[actions]
        old_action_probs = self.actor.predict(old_states)
        old_action_probs = np.clip(old_action_probs, 1e-10, 1.0)
        old_action_probs = old_action_probs * actions_one_hot
        old_action_probs = np.sum(old_action_probs, axis=1)

        with tf.GradientTape() as tape:
            new_action_probs = self.actor(old_states, training=True)
            new_action_probs = np.clip(new_action_probs, 1e-10, 1.0)
            new_action_probs = new_action_probs * actions_one_hot
            new_action_probs = np.sum(new_action_probs, axis=1)

            ratio = new_action_probs / old_action_probs

            surrogate1 = ratio * advantages
            surrogate2 = np.clip(ratio, 1 - self.epsilon, 1 + self.epsilon) * advantages
            actor_loss = -tf.reduce_mean(tf.minimum(surrogate1, surrogate2))

        actor_grads = tape.gradient(actor_loss, self.actor.trainable_variables)
        self.actor.optimizer.apply_gradients(zip(actor_grads, self.actor.trainable_variables))

        # Critic training
        with tf.GradientTape() as tape:
            values_pred = self.critic(old_states, training=True)
            critic_loss = tf.reduce_mean(tf.square(returns - values_pred))

        critic_grads = tape.gradient(critic_loss, self.critic.trainable_variables)
        self.critic.optimizer.apply_gradients(zip(critic_grads, self.critic.trainable_variables))

# Initialize PPO agent
agent = PPOAgent(num_states, num_actions)

# Training loop
num_episodes = 500
for episode in range(num_episodes):
    state = env.reset()
    done = False

    old_states = []
    actions = []
    rewards = []
    dones = []
    values = []

    while not done:
        # Collect data
        action = agent.choose_action(state)
        next_state, reward, done, _ = env.step(action)

        old_states.append(state)
        actions.append(action)
        rewards.append(reward)
        dones.append(done)
        values.append(agent.critic.predict(np.expand_dims(state, axis=0)))

        state = next_state

    # Train the agent
    agent.train(old_states, actions, rewards, dones, values)

    # Display rewards every 10 episodes
    if episode % 10 == 0:
        total_rewards = sum(rewards)
        print(f"Episode: {episode}, Rewards: {total_rewards}")

# Test the trained agent
state = env.reset()
done = False
total_rewards = 0

while not done:
    env.render()
    action = agent.choose_action(state)
    state, reward, done, _ = env.step(action)
    total_rewards += reward

print(f"Total Rewards: {total_rewards}")

env.close()
```

Make sure you have the OpenAI Gym package installed (`pip install gym`) and run the script. It will train a PPO agent on the CartPole-v1 environment and then test the trained agent. You should see the total rewards increasing as the agent learns to balance the pole on the cart.