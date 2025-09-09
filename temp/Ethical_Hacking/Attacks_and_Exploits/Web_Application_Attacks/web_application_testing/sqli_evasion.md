# SQL Injection (SQLi) Evasion Techniques

### 1. **Obfuscation Techniques**

#### **1.1 Comment Insertion**

- **Definition:** Use SQL comments to break up or hide parts of the SQL query.
- **Example:** `1' OR 1=1--` can be obfuscated as `1' OR 1=1 /* comment */--`.
- **Purpose:** Hide the true intent of the injected SQL code from detection mechanisms.

#### **1.2 Encoding**

- **Definition:** Encode the payload using various encoding schemes to evade detection.
- **Types:**
  - **URL Encoding:** Convert characters to their URL-encoded equivalents (e.g., `%27` for `'`).
  - **Hex Encoding:** Use hexadecimal values (e.g., `0x27` for `'`).
  - **Base64 Encoding:** Encode payloads in Base64 (e.g., `JTIxPTElM0El` for `1=1`).
- **Example:** `1' OR 1=1--` can be encoded as `1%27%20OR%201%3D1--`.

#### **1.3 Case Manipulation**

- **Definition:** Alter the case of SQL keywords and operators.
- **Example:** `SELECT` can be written as `sElEcT` or `SeLeCt`.
- **Purpose:** Bypass simple pattern-matching filters.

#### **1.4 String Concatenation**

- **Definition:** Break up SQL keywords or payloads using string concatenation functions.
- **Example:** `SELECT` can be broken as `CONCAT('SE', 'LECT')`.
- **Purpose:** Avoid detection by breaking up recognizable patterns.

### 2. **Advanced Evasion Techniques**

#### **2.1 Dynamic SQL Injection**

- **Definition:** Exploit SQL queries that are dynamically constructed at runtime.
- **Example:** Attacking a query that builds SQL commands using user input.
- **Purpose:** Bypass static query detection and filtering.

#### **2.2 Blind SQL Injection**

- **Definition:** Use techniques that do not return error messages but still manipulate the database.
- **Types:**
  - **Boolean-Based Blind SQLi:** Infer information based on changes in the response (e.g., `AND 1=1` vs. `AND 1=2`).
  - **Time-Based Blind SQLi:** Measure the time taken for responses to infer data (e.g., `SLEEP()` function).
- **Purpose:** Extract information without visible data or errors.

#### **2.3 Out-of-Band SQL Injection**

- **Definition:** Use alternative channels (e.g., DNS or HTTP requests) to extract data.
- **Example:** Using functions like `xp_cmdshell` to make the database server contact an attacker’s server.
- **Purpose:** Bypass direct response-based filtering and detection.

#### **2.4 Using Built-in Functions**

- **Definition:** Exploit SQL built-in functions to gather information or manipulate queries.
- **Example:** Using `UNION ALL SELECT` to combine results from multiple queries or `@@version` to get database version.
- **Purpose:** Extract information without directly triggering detection mechanisms.

### 3. **Other Evasion Techniques**

#### **3.1 Character Substitution**

- **Definition:** Replace SQL keywords or special characters with alternative representations.
- **Example:** Replacing `AND` with `+AND+` or using `CHAR()` function for character substitution.
- **Purpose:** Bypass keyword-based filters.

#### **3.2 Using Alternative Syntax**

- **Definition:** Exploit alternative SQL syntax or functions that achieve the same result.
- **Example:** Using `SELECT * FROM INFORMATION_SCHEMA.TABLES` instead of `SELECT * FROM sysobjects`.
- **Purpose:** Avoid detection by using less common SQL syntax or functions.

#### **3.3 HTTP Parameter Pollution**

- **Definition:** Inject malicious parameters into HTTP requests to alter the query.
- **Example:** Adding extra parameters to a URL or POST request to manipulate the SQL query.
- **Purpose:** Bypass input validation and filtering mechanisms.

#### **3.4 Advanced Encoding Techniques**

- **Definition:** Use more sophisticated encoding schemes to obscure payloads.
- **Types:**
  - **Double Encoding:** Encode the payload twice (e.g., `%2527` for `'`).
  - **Unicode Encoding:** Use Unicode representations to obfuscate SQL keywords.
- **Purpose:** Evade detection by making the payload less recognizable.

