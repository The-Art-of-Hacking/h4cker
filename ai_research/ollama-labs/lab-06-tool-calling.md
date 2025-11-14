# Lab 6: Tool Calling and Function Integration

## Objective
In this lab, you will learn how to implement tool calling (function calling) with Ollama models. You'll create functions that models can invoke, handle tool responses, build agent loops, and create practical applications that extend model capabilities with external tools.

## Prerequisites
- Completed Labs 1-5
- Python 3.8+ installed
- Ollama Python library installed (`pip install ollama`)
- Understanding of Python functions
- A tool-capable model (e.g., `qwen3`, `llama3.2`)

## Estimated Time
90-120 minutes

## Part 1: Understanding Tool Calling

### What is Tool Calling?

Tool calling allows language models to invoke external functions and use their results to provide more accurate, up-to-date, or computed answers.

### Use Cases
- Real-time data retrieval (weather, stock prices)
- Database queries
- File operations
- API calls
- Mathematical computations
- System information

## Part 2: Your First Tool Call

### Step 1: Pull a Tool-Capable Model

```bash
ollama pull qwen3
```

### Step 2: Simple Single Tool

Create `simple_tool.py`:

```python
from ollama import chat

def get_temperature(city: str) -> str:
    """Get the current temperature for a city
    
    Args:
        city: The name of the city
    
    Returns:
        The current temperature for the city
    """
    # Simulated temperature data
    temperatures = {
        "New York": "22°C",
        "London": "15°C",
        "Tokyo": "18°C",
        "Paris": "20°C",
        "Sydney": "25°C",
    }
    return temperatures.get(city, "Unknown")


# Initial user query
messages = [{'role': 'user', 'content': "What's the temperature in New York?"}]

# First API call - model decides to use the tool
response = chat(
    model='qwen3',
    messages=messages,
    tools=[get_temperature],
    think=True
)

# Add the assistant's response (with tool call) to messages
messages.append(response.message)

print("Model wants to call:", response.message.tool_calls[0].function.name)
print("With arguments:", response.message.tool_calls[0].function.arguments)

# Execute the tool if model requested it
if response.message.tool_calls:
    call = response.message.tool_calls[0]
    result = get_temperature(**call.function.arguments)
    
    # Add tool result to messages
    messages.append({
        'role': 'tool',
        'tool_name': call.function.name,
        'content': str(result)
    })
    
    # Final API call - model uses the tool result to answer
    final_response = chat(model='qwen3', messages=messages, tools=[get_temperature], think=True)
    print("\nFinal Answer:", final_response.message.content)
```

Run it:
```bash
python simple_tool.py
```

### Step 3: Understanding the Flow

The tool calling process:
1. User asks a question
2. Model decides it needs to call a tool
3. Model returns tool call request (function name + arguments)
4. You execute the function
5. You send the result back to the model
6. Model formulates final answer using the tool result

## Part 3: Multiple Tools

### Step 1: Create Multiple Related Tools

Create `weather_tools.py`:

```python
from ollama import chat

def get_temperature(city: str) -> str:
    """Get the current temperature for a city
    
    Args:
        city: The name of the city
    
    Returns:
        The current temperature for the city
    """
    temperatures = {
        "New York": "22°C",
        "London": "15°C",
        "Tokyo": "18°C",
    }
    return temperatures.get(city, "Unknown")


def get_conditions(city: str) -> str:
    """Get the current weather conditions for a city
    
    Args:
        city: The name of the city
    
    Returns:
        The current weather conditions for the city
    """
    conditions = {
        "New York": "Partly cloudy",
        "London": "Rainy",
        "Tokyo": "Sunny"
    }
    return conditions.get(city, "Unknown")


# User asks about multiple aspects
messages = [{
    'role': 'user',
    'content': 'What are the weather conditions and temperature in Tokyo?'
}]

response = chat(
    model='qwen3',
    messages=messages,
    tools=[get_temperature, get_conditions],
    think=True
)

messages.append(response.message)

# Process all tool calls
if response.message.tool_calls:
    for call in response.message.tool_calls:
        print(f"Calling: {call.function.name} with {call.function.arguments}")
        
        # Execute appropriate function
        if call.function.name == 'get_temperature':
            result = get_temperature(**call.function.arguments)
        elif call.function.name == 'get_conditions':
            result = get_conditions(**call.function.arguments)
        else:
            result = 'Unknown tool'
        
        # Add result to messages
        messages.append({
            'role': 'tool',
            'tool_name': call.function.name,
            'content': str(result)
        })
    
    # Get final response
    final_response = chat(model='qwen3', messages=messages, tools=[get_temperature, get_conditions], think=True)
    print("\nFinal Answer:", final_response.message.content)
```

## Part 4: Parallel Tool Calling

### Step 1: Tools Called in Parallel

Create `parallel_tools.py`:

```python
from ollama import chat

def get_temperature(city: str) -> str:
    """Get the current temperature for a city"""
    return f"{city}: 20°C"

def get_conditions(city: str) -> str:
    """Get weather conditions for a city"""
    return f"{city}: Sunny"

# Query for multiple cities
messages = [{
    'role': 'user',
    'content': 'What is the weather like in New York and London?'
}]

response = chat(model='qwen3', messages=messages, tools=[get_temperature, get_conditions], think=True)
messages.append(response.message)

print(f"Model requested {len(response.message.tool_calls)} tool calls\n")

# Execute all tool calls
for call in response.message.tool_calls:
    print(f"Tool: {call.function.name}, Args: {call.function.arguments}")
    
    if call.function.name == 'get_temperature':
        result = get_temperature(**call.function.arguments)
    elif call.function.name == 'get_conditions':
        result = get_conditions(**call.function.arguments)
    
    messages.append({
        'role': 'tool',
        'tool_name': call.function.name,
        'content': result
    })

# Final response
final = chat(model='qwen3', messages=messages, tools=[get_temperature, get_conditions])
print("\n" + final.message.content)
```

## Part 5: Agent Loop - Multi-Turn Tool Calling

### Step 1: Mathematical Agent

Create `math_agent.py`:

```python
from ollama import chat, ChatResponse

def add(a: int, b: int) -> int:
    """Add two numbers
    
    Args:
        a: The first number
        b: The second number
    
    Returns:
        The sum of the two numbers
    """
    return a + b

def multiply(a: int, b: int) -> int:
    """Multiply two numbers
    
    Args:
        a: The first number
        b: The second number
    
    Returns:
        The product of the two numbers
    """
    return a * b

available_functions = {
    'add': add,
    'multiply': multiply,
}

# Complex mathematical question requiring multiple steps
messages = [{'role': 'user', 'content': 'What is (15 + 27) * 8?'}]

print("Starting agent loop...\n")
iteration = 0

while True:
    iteration += 1
    print(f"--- Iteration {iteration} ---")
    
    response: ChatResponse = chat(
        model='qwen3',
        messages=messages,
        tools=[add, multiply],
        think=True,
    )
    
    messages.append(response.message)
    
    if response.message.thinking:
        print(f"Model thinking: {response.message.thinking[:100]}...")
    
    if response.message.tool_calls:
        print(f"Tool calls requested: {len(response.message.tool_calls)}")
        
        for tc in response.message.tool_calls:
            if tc.function.name in available_functions:
                print(f"  - Calling {tc.function.name}{tc.function.arguments}")
                result = available_functions[tc.function.name](**tc.function.arguments)
                print(f"    Result: {result}")
                
                messages.append({
                    'role': 'tool',
                    'tool_name': tc.function.name,
                    'content': str(result)
                })
    else:
        # No more tool calls - we have the final answer
        print(f"\nFinal Answer: {response.message.content}")
        break
    
    if iteration > 10:  # Safety limit
        print("Max iterations reached")
        break
```

Run it:
```bash
python math_agent.py
```

## Part 6: Real-World Tools

### Step 1: File Operations Tool

Create `file_tools.py`:

```python
from ollama import chat
import os

def list_files(directory: str = ".") -> str:
    """List files in a directory
    
    Args:
        directory: Path to the directory (default: current directory)
    
    Returns:
        Comma-separated list of files
    """
    try:
        files = os.listdir(directory)
        return ", ".join(files)
    except Exception as e:
        return f"Error: {str(e)}"

def read_file(filename: str) -> str:
    """Read contents of a file
    
    Args:
        filename: Name of the file to read
    
    Returns:
        File contents
    """
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

# Example usage
messages = [{'role': 'user', 'content': 'What Python files are in the current directory?'}]

while True:
    response = chat(model='qwen3', messages=messages, tools=[list_files, read_file])
    messages.append(response.message)
    
    if response.message.tool_calls:
        for call in response.message.tool_calls:
            if call.function.name == 'list_files':
                result = list_files(**call.function.arguments)
            elif call.function.name == 'read_file':
                result = read_file(**call.function.arguments)
            else:
                result = 'Unknown tool'
            
            messages.append({
                'role': 'tool',
                'tool_name': call.function.name,
                'content': result
            })
    else:
        print(response.message.content)
        break
```

### Step 2: API Integration Tool

Create `api_tools.py`:

```python
from ollama import chat
import requests
import json

def get_github_user(username: str) -> str:
    """Get GitHub user information
    
    Args:
        username: GitHub username
    
    Returns:
        JSON string with user information
    """
    try:
        response = requests.get(f"https://api.github.com/users/{username}")
        if response.status_code == 200:
            data = response.json()
            return json.dumps({
                'name': data.get('name'),
                'bio': data.get('bio'),
                'public_repos': data.get('public_repos'),
                'followers': data.get('followers')
            })
        else:
            return f"Error: User not found"
    except Exception as e:
        return f"Error: {str(e)}"

messages = [{'role': 'user', 'content': 'Tell me about the GitHub user torvalds'}]

response = chat(model='qwen3', messages=messages, tools=[get_github_user])
messages.append(response.message)

if response.message.tool_calls:
    call = response.message.tool_calls[0]
    result = get_github_user(**call.function.arguments)
    
    messages.append({
        'role': 'tool',
        'tool_name': call.function.name,
        'content': result
    })
    
    final = chat(model='qwen3', messages=messages, tools=[get_github_user])
    print(final.message.content)
```

Note: You'll need to install `requests`:
```bash
pip install requests
```

## Part 7: Tool Calling with Streaming

### Step 1: Streaming Agent

Create `streaming_agent.py`:

```python
from ollama import chat

def get_temperature(city: str) -> str:
    """Get temperature for a city"""
    return f"{city}: 22°C"

messages = [{'role': 'user', 'content': "What's the temperature in Paris?"}]

while True:
    stream = chat(
        model='qwen3',
        messages=messages,
        tools=[get_temperature],
        stream=True,
        think=True,
    )
    
    thinking = ''
    content = ''
    tool_calls = []
    done_thinking = False
    
    # Accumulate streamed chunks
    for chunk in stream:
        if chunk.message.thinking:
            thinking += chunk.message.thinking
            print(chunk.message.thinking, end='', flush=True)
        
        if chunk.message.content:
            if not done_thinking:
                done_thinking = True
                print('\n\nResponse: ', end='')
            content += chunk.message.content
            print(chunk.message.content, end='', flush=True)
        
        if chunk.message.tool_calls:
            tool_calls.extend(chunk.message.tool_calls)
    
    print()  # New line
    
    # Add accumulated response to messages
    if thinking or content or tool_calls:
        messages.append({
            'role': 'assistant',
            'thinking': thinking,
            'content': content,
            'tool_calls': tool_calls
        })
    
    # Execute tools if requested
    if not tool_calls:
        break
    
    for call in tool_calls:
        result = get_temperature(**call.function.arguments)
        print(f"\nExecuted: {call.function.name} -> {result}")
        messages.append({
            'role': 'tool',
            'tool_name': call.function.name,
            'content': result
        })
```

## Exercises

### Exercise 1: Calculator Agent

Create a calculator agent with these tools:
- `add(a, b)`
- `subtract(a, b)`
- `multiply(a, b)`
- `divide(a, b)`
- `power(base, exponent)`

Test with: "Calculate ((10 + 5) * 3) ^ 2"

### Exercise 2: Database Query Tool

Create tools that simulate database queries:
- `get_user_by_id(user_id: int)`
- `get_orders_for_user(user_id: int)`
- `get_product_details(product_id: int)`

Use a simple dictionary as your "database" and test queries like:
"Show me all orders for user 123 and the details of their products"

### Exercise 3: System Information Tool

Create tools that provide system information:
- `get_disk_usage()` - Returns disk space info
- `get_cpu_info()` - Returns CPU usage
- `get_memory_info()` - Returns memory usage
- `get_current_time()` - Returns current time

### Exercise 4: Text Processing Tools

Create text analysis tools:
- `count_words(text: str)`
- `find_emails(text: str)`
- `extract_urls(text: str)`
- `summarize_text(text: str)` - Use another Ollama call

### Exercise 5: Multi-Step Research Assistant

Create a research assistant that:
1. Searches for information (simulated)
2. Reads sources
3. Synthesizes information
4. Provides cited answers

## Lab Questions

1. What is the difference between single-shot and multi-turn tool calling?
2. When would you use parallel tool calls versus sequential calls?
3. How does the model know which tools are available?
4. What role does the function docstring play in tool calling?
5. How can you prevent infinite loops in agent loops?
6. What are the security considerations when allowing models to call tools?

## Advanced Challenges

### Challenge 1: Smart Home Controller

Build a simulated smart home system with tools for:
- Controlling lights
- Adjusting temperature
- Checking security
- Playing music

Create natural language interface: "Turn on living room lights and set temperature to 22 degrees"

### Challenge 2: Code Execution Sandbox

Create a **safe** code execution tool that:
1. Accepts Python code
2. Validates it for safety
3. Executes in a restricted environment
4. Returns results

**Warning**: Be very careful with code execution!

### Challenge 3: Multi-Source Information Gatherer

Build an agent that:
1. Queries multiple data sources (APIs, files, databases)
2. Aggregates information
3. Resolves conflicts
4. Provides comprehensive answers

## Best Practices

### 1. Tool Design
- Clear, descriptive function names
- Detailed docstrings
- Type hints for parameters
- Handle errors gracefully

### 2. Security
- Validate tool inputs
- Limit tool capabilities
- Implement timeouts
- Log tool executions
- Never execute arbitrary code without sandboxing

### 3. Agent Loops
- Set iteration limits
- Monitor for infinite loops
- Add escape conditions
- Log each iteration

### 4. Error Handling
```python
def safe_tool_call(function, **kwargs):
    try:
        return function(**kwargs)
    except Exception as e:
        return f"Error: {str(e)}"
```

## Troubleshooting

### Issue: Model doesn't call tools
- **Solution**: Ensure docstrings are detailed, try a different model (qwen3, llama3.2)

### Issue: Wrong arguments passed to tools
- **Solution**: Add clear parameter descriptions, use type hints

### Issue: Infinite loop in agent
- **Solution**: Add iteration counter and max limit

### Issue: Tools execute too slowly
- **Solution**: Implement async tools, add caching, optimize tool code

## Summary

In this lab, you learned how to:
- Implement tool calling with Ollama models
- Create single and multiple tool integrations
- Build agent loops for multi-step reasoning
- Handle parallel tool calls
- Stream tool-using conversations
- Integrate real-world APIs and system functions
- Implement best practices for tool safety and reliability

## Next Steps

Continue to **Lab 7: Vision Models - Working with Images** to learn how to work with multimodal models that can process both text and images.

