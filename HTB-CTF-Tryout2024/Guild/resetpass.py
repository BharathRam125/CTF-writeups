import hashlib

# Email input
email = "57537447386c366e@master.guild"

# Generate SHA-256 hash of the email
hashed = hashlib.sha256(email.encode()).hexdigest()

# Create the reset password link
reset_link = f"changepasswd/{hashed}"

# Print the reset link
print(reset_link)

