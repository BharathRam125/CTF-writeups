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
    host = "94.237.60.154"  # Replace with actual host
    port = 45498            # Replace with actual port
    
    # Establish connection
    conn = remote(host, port)
    
    try:
        for test_num in range(1, 101):  # Loop for 100 test cases, test_num is 1-indexed
            # Print the current test number
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

