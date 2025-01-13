
# UofTCTF 2025 Writeup

## **1. Challenge Name:** Prismatic Blogs  
**Category:** Web  
**Vulnerability:** ORM Leak

### **Introduction**
The challenge involved a web application called **Prismatic Blogs**. The backend used **Express.js** and the **Prisma Client** for database interactions. The main vulnerability exploited was an **ORM Leak** that allowed unauthorized access to sensitive data by manipulating relational filters.

### **Schema and Backend Analysis**
The application used **SQLite** as the database provider, with the following Prisma schema:

```prisma
// Database Configuration
datasource db {
  provider = "sqlite"
  url      = "file:./database.db"
}

generator client {
  provider = "prisma-client-js"
}

// User Table
model User {
  id        Int      @id @default(autoincrement())
  createdAt DateTime @default(now())
  name      String   @unique
  password  String
  posts     Post[]
}

// Post Table
model Post {
  id        Int      @id @default(autoincrement())
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  published Boolean  @default(false)
  title     String
  body      String
  author    User     @relation(fields: [authorId], references: [id])
  authorId  Int
}
```

The **`/api/posts`** endpoint retrieves blog posts using the following code:

```javascript
app.get("/api/posts", async (req, res) => {
  try {
    const query = req.query;
    query.published = true;  // Enforcing published=true
    const posts = await prisma.post.findMany({ where: query });
    res.json({ success: true, posts });
  } catch (error) {
    res.json({ success: false, error });
  }
});
```

This implementation forces `published=true` before querying the database, preventing users from accessing unpublished posts.

### Observations:
- Prisma coerces query parameters into **strings**.
  - Example: `authorId=1` becomes `authorId='1'`
  - `published=false` becomes `published='false'`
- **Only string fields** can be used for injection.

Attempts to set `published=false` were overridden by the backend logic:
```bash
GET /api/posts?published=false
```
This query was internally changed to `published=true`.


### **Exploitation Process**
### **Relational Filter Manipulation**
I explored relational filters in Prisma:
```bash
GET /api/posts?[author][name]=Bob
```
This translated to:
```json
{
  "author": { "name": "Bob" },
  "published": true
}
```
This query worked but only returned **published posts**.

### **Approach 1: Targeting Passwords [Tried and dropped]**
I realized that user passwords were stored in the **User** table. By using **relational filters**, I could extract passwords character by character.

I used **Burp Suite Intruder** to automate the process with the following payload:
```bash
GET /api/posts?[author][password][startsWith]=§a§
```
This revealed **Tommy's password**. However, all characters were uppercase, indicating that Prisma's `startsWith` filter is **case-insensitive**.

I used a simple **alphanumeric payload list** (A-Z, a-z, 0-9) in **Burp Suite Intruder** to test each character sequentially.This approach successfully revealed Tommy's password, but the password was all uppercase.  

Note : We can try `le` and `ge` filters to check for case of each character but time consuming. 

### **Approach 2: Flag Retrieval [Success]**
I targeted the **Post** table to retrieve the flag stored in an unpublished post using this query:
```bash
GET /api/posts?[author][posts][some][body][contains]=uoftctf{§a§
```
This query checks for any **posts** related to an **author** where the **body** contains a substring starting with a specific character. Since Prisma filters like `contains` are case-insensitive. However, I decided to try lowercase characters, as previously solved flags in UofTCTF followed an all-lowercase pattern.

Using **Burp Suite Intruder**, I automated the process to retrieve the flag character by character by modifying the payload to:
```bash
GET /api/posts?[author][posts][some][body][contains]=uoftctf{abc...}
```

### **Response Analysis:**
The response did not directly return the unpublished flag post because of the `published=true` condition. Instead, it returned **all other published posts** of that author. 

By analyzing the response lengths in **Burp Suite Intruder**, I identified that larger responses indicated the presence of additional posts by the same author. This allowed me to infer the presence of the flag post and extract the flag.

For example:
```bash
GET /api/posts?[author][posts][some][body][contains]=uoftctf{u51
```
I observed that responses with more content had longer lengths, indicating posts belonging to the same author were returned in the response. Shorter responses indicated no match.

 

### Key Insights:
- Prisma's relational filters (`contains`, `startsWith`, `endsWith`, `some`) can be exploited to access unauthorized data.
- Query parameters are treated as **strings**, even for integer fields.
- Filters are **case-insensitive**.
- Previous UofTCTF flags followed an all-lowercase pattern, which gave me the confidence to try lowercase characters.


### **Flag:**
```
uoftctf{u51n6_0rm5_d035_n07_m34n_1nj3c710n5_c4n7_h4pp3n}
```

---
## **2. Challenge Name:** Scavenger Hunt 
**Category:** Web  

### Challenge Details:
The flag is split across different parts of the website. To uncover it, inspect the following elements using the browser's inspect tool:
- `robots.txt`
- CSS files
- HTML source code
- Cookies

### Flag Parts:
1. `ju57_k33p_`
2. `c4lm_4nd_`
3. `1n5p3c7_`
4. `411_7h3_`
5. `4pp5_`
6. `50urc3_`
7. `c0d3!!`

### Flag:
`uoftctf{ju57_k33p_c4lm_4nd_1n5p3c7_411_7h3_4pp5_50urc3_c0d3!!}`
