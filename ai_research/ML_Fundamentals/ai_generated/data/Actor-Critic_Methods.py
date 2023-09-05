Sure! Here's an example of a Python script that demonstrates Actor-Critic Methods using the OpenAI Gym environment and the Keras library:

```python
import gym
import numpy as np
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam


class ActorCriticAgent:
    def __init__(self, state_size, action_size):
        self.state_size = state_size
        self.action_size = action_size

        # Hyperparameters for the agent
        self.lr_actor = 0.001
        self.lr_critic = 0.005
        self.discount_factor = 0.99

        # Create models for the actor and critic
        self.actor = self.build_actor()
        self.critic = self.build_critic()

    def build_actor(self):
        input = Input(shape=(self.state_size,))
        dense = Dense(24, activation='relu')(input)
        probs = Dense(self.action_size, activation='softmax')(dense)
        model = Model(inputs=input, outputs=probs)
        model.compile(loss='categorical_crossentropy', optimizer=Adam(lr=self.lr_actor))
        return model

    def build_critic(self):
        input = Input(shape=(self.state_size,))
        dense = Dense(24, activation='relu')(input)
        value = Dense(1, activation='linear')(dense)
        model = Model(inputs=input, outputs=value)
        model.compile(loss='mse', optimizer=Adam(lr=self.lr_critic))
        return model

    def get_action(self, state):
        state = np.reshape(state, [1, self.state_size])
        probs = self.actor.predict(state)[0]
        action = np.random.choice(self.action_size, p=probs)
        return action

    def train_model(self, state, action, reward, next_state, done):
        target = np.zeros((1, self.action_size))
        advantages = np.zeros((1, self.action_size))

        value = self.critic.predict(state)[0]
        next_value = self.critic.predict(next_state)[0]

        if done:
            advantages[0][action] = reward - value
            target[0][action] = reward
        else:
            advantages[0][action] = reward + self.discount_factor * (next_value) - value
            target[0][action] = reward + self.discount_factor * next_value

        self.actor.fit(state, advantages, epochs=1, verbose=0)
        self.critic.fit(state, target, epochs=1, verbose=0)


if __name__ == "__main__":
    # Create the environment
    env = gym.make('CartPole-v1')
    state_size = env.observation_space.shape[0]
    action_size = env.action_space.n

    # Create an instance of the agent
    agent = ActorCriticAgent(state_size, action_size)

    scores, episodes = [], []
    EPISODES = 100

    for episode in range(EPISODES):
        done = False
        score = 0
        state = env.reset()

        while not done:
            action = agent.get_action(state)
            next_state, reward, done, info = env.step(action)
            agent.train_model(state, action, reward, next_state, done)
            score += reward
            state = next_state

            if done:
                scores.append(score)
                episodes.append(episode)
                print("Episode:", episode, "Score:", score)

    # Plot the scores
    import matplotlib.pyplot as plt
    plt.plot(episodes, scores, 'b')
    plt.xlabel("Episode")
    plt.ylabel("Score")
    plt.show()
```

In this script, we create an `ActorCriticAgent` class that represents the agent using Actor-Critic Methods. We then use this agent to train on the `CartPole-v1` environment from OpenAI Gym. The agent has an actor model that outputs action probabilities and a critic model that predicts values. These models are trained using the actor-critic algorithm in the `train_model` method.

During training, the agent selects actions based on the actor model's output and updates its models using the observed rewards and states. The scores are stored and plotted at the end to visualize the agent's performance over multiple episodes.

Please make sure you have installed the required libraries (`gym`, `numpy`, `tensorflow`, `keras`, and `matplotlib`) before running this script.