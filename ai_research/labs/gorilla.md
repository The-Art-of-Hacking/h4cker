# Using Gorilla CLI

To complete this lab you only need a Linux computer with Python. For your convenience, you can use the terminal window in the following interactive lab:
https://learning.oreilly.com/scenarios/ethical-hacking-active/9780137835720X003/

TIP: There are several Cybersecurity-related interactive labs that are free with your O'Reilly subscription at: https://hackingscenarios.com

## What is Gorilla?

The University of California Berkeley in collaboration with Microsoft have unveiled "Gorilla", a sophisticated model founded on the LLaMA model, reputed to surpass GPT-4 in generating API calls proficiently. A notable characteristic of Gorilla is its cohesive function with a document retriever, facilitating it to adapt smoothly to alterations in documents throughout the testing phase. This flexibility is vital, particularly when navigating the fluctuating nature of API documentation and versions. Moreover, Gorilla has the capability to significantly mitigate the hallucination issues, which is a common obstacle faced when utilizing Large Language Models (LLMs) directly.

They also created "APIBench", a comprehensive dataset that includes APIs from notable platforms such as HuggingFace, TorchHub, and TensorHub. The operational efficacy of Gorilla highlights the enormous potential harbored by this kind of LLMs and their applications. This amalgamation not only assures finer tool precision but also the capacity to stay abreast with the continuously updating documentation. Those keen on delving deeper into Gorilla can find the models and corresponding code at: https://github.com/ShishirPatil/gorilla. More details and the research paper are available at: https://gorilla.cs.berkeley.edu/

## Using Gorilla CLI
I have a few examples of [using Gorilla for Cybersecurity in this article](https://becomingahacker.org/using-gorilla-pioneering-api-interactions-in-large-language-models-for-cybersecurity-operations-252ce018be6b).
However, let's go over a few examples:

- **Step 1**: You have access to labs and playgrounds in O'Reilly. Navigate to the following lab and maximize the terminal window: https://learning.oreilly.com/scenarios/ethical-hacking-active/9780137835720X003/
- **Step 2**: Install gorilla-cli using the command `pip3 install gorilla-cli`
<img width="871" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/4c085e17-71ad-41e7-8776-683eded946ba">

- **Step 3**: Start interacting with it. The following is an example of a prompt to learn how can you see your IP address in Linux:
<img width="1685" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/8d599cb9-3b32-44a4-ae9c-ac185e5a0275">

It will always give you different options to select from. After selecting the most appropriate option, the command is executed:
<img width="1597" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/98c9527a-a3ce-4912-8a75-165939f6e8b8">

- **Step 4**: This is another example:
<img width="1092" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/ec147762-f1ff-4759-90e4-fa27b3ca974a">
<img width="1582" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/4a8d06ec-6a03-4faf-bea2-187645d732c8">

- **Step 5**: How about Python?
  <img width="1593" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/06a07b67-0b5d-43c7-a37a-d4de19a54347">

Keep playing with it... The amazing part about Gorilla is the extensive APIs it supports.




