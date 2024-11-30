# Hack the Box CTF Try Out 2024 - Dynamic Paths


### Challenge Description

On your way to the vault, you decide to follow the underground tunnels, a vast and complicated network of paths used by early humans before the great war. From your previous hack, you already have a map of the tunnels, along with information like distances between sections of the tunnels. While you were studying it to figure out your path, a wild super mutant behemoth came behind you and started attacking. Without a second thought, you run into the tunnel, but the behemoth came running inside as well. 

Can you use your extensive knowledge of the underground tunnels to reach your destination fast and outrun the behemoth?

### Objective

The goal is to navigate through the underground tunnel system by minimizing the sum of the distances as you move through the grid of tunnels. You start from the top-left corner and need to reach the bottom-right corner of the grid. You can only move **right** or **down**.

The grid's values represent the distances between the sections of the tunnels. You need to compute the minimum sum of the distances from the top-left to the bottom-right corner.

#### Example

**Input:**
4 3 
2 5 1 9 2 3 9 1 3 11 7 4

**Grid Representation:**
2 5 1 \
9 2 3 \
9 1 3 \
11 7 4


**Optimal Path:**
- 2 -> 5 -> 2 -> 1 -> 3 -> 4  
- **Minimum sum:** 17

### Approach

This challenge is a **Dynamic Programming** problem where you need to calculate the minimum path sum. The task involves moving from the top-left to the bottom-right of the grid, while only being allowed to move **down** or **right**.

The solution can be approached as follows:

1. **Dynamic Programming Table (DP Table):**
   - Create a table where each cell represents the minimum sum to reach that cell from the top-left.
   - The cell at position `[i][j]` will store the minimum sum of distances required to reach that point from the start.

2. **Initialization:**
   - The top-left corner (starting point) is initialized with its own value, as that's where we start.
   - The first row and first column are filled by cumulatively adding the values as you can only come from one direction (either from the left for the row or from above for the column).

3. **Filling the DP Table:**
   - For each remaining cell, you can either come from the left or from above. Take the minimum of these two options and add the current cell's value to it.

4. **Final Answer:**
   - The value at the bottom-right corner of the grid will hold the minimum sum path.

### Solution Code

```python
from pwn import *

def solve_min_path_sum(grid, rows, cols):
    # Initialize DP table
    dp = [[0] * cols for _ in range(rows)]
    dp[0][0] = grid[0][0]
    
    # Fill the first row
    for j in range(1, cols):
        dp[0][j] = dp[0][j - 1] + grid[0][j]
    
    # Fill the first column
    for i in range(1, rows):
        dp[i][0] = dp[i - 1][0] + grid[i][0]
    
    # Fill the rest of the table
    for i in range(1, rows):
        for j in range(1, cols):
            dp[i][j] = min(dp[i - 1][j], dp[i][j - 1]) + grid[i][j]
    
    return dp[-1][-1]

def main():
    host = "<ip>"  # Replace with actual host
    port = <port>  # Replace with actual port
    
    # Establish connection
    conn = remote(host, port)
    
    try:
        for test_num in range(1, 101):  # Loop for 100 test cases
            print(f"Test {test_num}/100")
            
            # Wait until the 'Test' keyword appears and discard the 'Test x/100' line
            conn.recvuntil(b'Test')
            conn.recvline()  # This consumes the "Test x/100" line
            
            # Now receive the next two lines: dimensions and grid values
            dimensions = conn.recvline().decode().strip()  # First line: dimensions
            grid_values = conn.recvline().decode().strip()  # Second line: grid values
            
            # Parse dimensions and grid values
            try:
                rows, cols = map(int, dimensions.split())
                grid_values = list(map(int, grid_values.split()))
                grid = [grid_values[i * cols:(i + 1) * cols] for i in range(rows)]
            except ValueError as e:
                print(f"Parsing Error: {e}")
                break
            
            # Solve the problem
            result = solve_min_path_sum(grid, rows, cols)
            
            # Send the result back to the server
            conn.sendline(str(result).encode())  # Convert the result to bytes before sending
            
            # Receive the server's response and print it
            response = conn.recvline().decode().strip()  # Read the server's response
            print(f"Server Response: {response}")
            
            print(f"Result Sent: {result}")  # Print the result sent to the server
    
    except Exception as e:
        print(f"Error during interaction: {e}")
    
    finally:
        conn.close()

if __name__ == "__main__":
    main()
```

Explanation:
solve_min_path_sum(grid, rows, cols): This function calculates the minimum sum of distances to travel from the top-left corner to the bottom-right corner using dynamic programming.
Main logic: The main function connects to the CTF server, iterates through the test cases, parses the grid dimensions and values, solves for the minimum path sum, and sends the result back to the server.


