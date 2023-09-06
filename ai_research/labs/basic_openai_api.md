# Using the OpenAI API with Python 

### Step 1: Setting Up the Environment

1. **Install Python**: Make sure you have Python 3.x installed. You can download it from the [official website](https://www.python.org/).
2. **Set Up a Virtual Environment** (optional but recommended):
   ```bash
   python3 -m venv openai-lab-env
   source openai-lab-env/bin/activate  # On Windows, use `openai-lab-env\Scripts\activate`
   ```
3. **Install Necessary Packages**:
   ```bash
   pip3 install openai requests
   ```

### Step 2: Configuring API Credentials

4. **Register on OpenAI**:
   - Go to the [OpenAI website](https://www.openai.com/) and register to obtain API credentials.
   
5. **Configure API Credentials**:
   - Store your API credentials securely, possibly using environment variables. In your terminal, you can set it up using the following command (replace `your_api_key_here` with your actual API key):
     ```bash
     export OPENAI_API_KEY=your_api_key_here
     ```

### Step 3: Making API Calls

6. **Create a Python Script**:
   - Create a new Python script (let’s name it `openai_lab.py`) and open it in a text editor.

7. **Import Necessary Libraries**:
   ```python
   import openai
   openai.api_key = 'your_api_key_here'  # Alternatively, use the environment variable to store the API key
   ```

8. **Make a Simple API Call**:
   ```python
    # Generate the AI response using the GPT-3.5 model (16k)
    # https://beta.openai.com/docs/api-reference/create-completion
    response = openai.ChatCompletion.create(
      model="gpt-3.5-turbo-16k",
      messages=prompt,
      max_tokens=15000
    )

    # print the AI response
    print(response.choices[0].message.content)
   ```

### Step 4: Experimenting with the API

9. **Experiment with Different Parameters**:
   - Modify the `max_tokens`, `temperature`, and `top_p` parameters and observe how the responses change.

10. **Handle API Responses**:
    - Learn how to handle API responses and extract the required information.

### Step 5: Building a Simple Application

11. **Develop a Simple Application**:
    - Create a more complex script that could function as a Q&A system or a content generation tool. You can use [the "Article Generator" example](https://github.com/The-Art-of-Hacking/h4cker/blob/master/ai_research/ML_Fundamentals/ai_generated/article_generator.py) we discussed during class for reference. 
    
12. **Testing Your Application**:
    - Run various tests to ensure the functionality and robustness of your application.

