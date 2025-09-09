# Useful LDAP Queries

Lightweight Directory Access Protocol (LDAP) is a protocol used to access and manage directory information services over an IP network. In Windows Active Directory (AD) domains, LDAP plays a crucial role in storing and retrieving a vast amount of information, including user accounts, group memberships, computer accounts, and more. For penetration testers and security professionals, querying LDAP can reveal valuable insights into the domain's structure, potential misconfigurations, and vulnerabilities.


## Understanding LDAP Query Operators

Some LDAP queries utilize special comparison operators, particularly when filtering based on attributes like `userAccountControl`. Understanding these operators is essential for crafting effective queries.

| Operator                               | OID                      | Description                                                                                                                                                                                                                                                     |
|----------------------------------------|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **LDAP_MATCHING_RULE_BIT_AND**         | `1.2.840.113556.1.4.803` | Performs a bitwise "AND" operation. Useful for checking if specific bits are set in an attribute like `userAccountControl`.                                                                                                                                     |
| **LDAP_MATCHING_RULE_BIT_OR**          | `1.2.840.113556.1.4.804` | Performs a bitwise "OR" operation.                                                                                                                                                                                                                              |
| **LDAP_MATCHING_RULE_TRANSITIVE_EVAL** | `1.2.840.113556.1.4.1941`| Performs a recursive search of a link attribute. Useful for finding all members of a group, including nested group members. [See Microsof's documentation](https://docs.microsoft.com/en-us/windows/win32/adschema/adschema-search-filter-syntax) |
| **LDAP_MATCHING_RULE_DN_WITH_DATA**    | `1.2.840.113556.1.4.2253`| Matches portions of values of syntax `Object(DN-String)` and `Object(DN-Binary)`.                                                                                                                                                                               |

---

## Users

### List All Users

To retrieve all user accounts in the domain, you can use the following query:

```ldap
(&(objectCategory=person)(objectClass=user))
```

- **Explanation:**
  - `(objectCategory=person)`: Filters objects categorized as a person.
  - `(objectClass=user)`: Ensures the object is a user account.

**Example Command:**

```bash
ldapsearch -x -b "dc=hacker26,dc=com" "(&(objectCategory=person)(objectClass=user))"
```

### List All Kerberoastable Users

Kerberoasting is an attack technique that targets Service Principal Names (SPNs) associated with user accounts. To find all kerberoastable users:

```ldap
(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

- **Explanation:**
  - `(objectClass=user)`: Targets user accounts.
  - `(servicePrincipalName=*)`: Selects users with an SPN defined.
  - `(!(cn=krbtgt))`: Excludes the `krbtgt` account.
  - `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`: Excludes disabled accounts.

**Additional Example:**

To include only accounts with a specific SPN:

```ldap
(&(objectClass=user)(servicePrincipalName=HTTP/*))
```

### List All AS-REP Roastable Users

AS-REP roasting targets user accounts that do not require Kerberos preauthentication. To find such users:

```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

- **Explanation:**
  - The `4194304` flag corresponds to `DONT_REQ_PREAUTH`.

### Find Users Who Need to Change Password on Next Login

```ldap
(&(objectCategory=user)(pwdLastSet=0))
```

- **Explanation:**
  - `(pwdLastSet=0)`: Indicates the password must be changed at next logon.

### Find Users Who Are Almost Locked Out

Assuming the account lockout threshold is 5, find users with 4 failed attempts:

```ldap
(&(objectCategory=user)(badPwdCount>=4))
```

- **Explanation:**
  - `(badPwdCount>=4)`: Users with 4 or more bad password attempts.

### Find Users with Passwords in Description

Sometimes, passwords are mistakenly stored in the `description` attribute:

```ldap
(&(objectCategory=user)(|(description=*pass*)(description=*pwd*)))
```

- **Explanation:**
  - Searches for `pass` or `pwd` in the `description` field.

**Additional Example:**

To find users with passwords in `comment` or `info` fields:

```ldap
(&(objectCategory=user)(|(comment=*pass*)(info=*pass*)))
```

### List Users Protected by `adminCount`

The `adminCount` attribute indicates that an object has had its Access Control Lists (ACLs) modified due to membership in administrative groups.

```ldap
(&(objectCategory=user)(adminCount=1))
```

- **Explanation:**
  - Identifies users with `adminCount` set to `1`, implying administrative privileges.

---

## Groups

### List All Groups

Retrieve all group objects in the domain:

```ldap
(objectCategory=group)
```

**Example Command:**

```bash
ldapsearch -x -b "dc=hacker26,dc=com" "(objectCategory=group)"
```

### List Groups Protected by `adminCount`

```ldap
(&(objectCategory=group)(adminCount=1))
```

- **Explanation:**
  - Identifies groups with administrative privileges.

### Find Groups with Specific Members

To find groups that a particular user is a member of:

```ldap
(&(objectCategory=group)(member=cn=Username,ou=Users,dc=hacker26,dc=com))
```

- **Explanation:**
  - Replace `cn=Username,ou=Users,dc=hacker26,dc=com` with the user's distinguished name (DN).

### List Empty Groups

Groups without members might indicate misconfigurations:

```ldap
(&(objectCategory=group)(!(member=*)))
```

---

## Services

### List All Service Principal Names (SPNs)

SPNs are unique identifiers for services running on servers. To list all SPNs:

```ldap
(servicePrincipalName=*)
```

**Example Command:**

```bash
ldapsearch -x -b "dc=hacker26,dc=com" "(servicePrincipalName=*)"
```

### List Specific Services Based on SPNs

To find specific services, filter by the SPN prefix. For example, to find HTTP services:

```ldap
(servicePrincipalName=HTTP/*)
```

- **Explanation:**
  - `HTTP/*`: Matches any SPN starting with `HTTP/`.

**Additional Examples:**

- Find MSSQL services:

  ```ldap
  (servicePrincipalName=MSSQLSvc/*)
  ```

- Find LDAP services:

  ```ldap
  (servicePrincipalName=ldap/*)
  ```

### Find Accounts with Duplicate SPNs

Duplicate SPNs can cause authentication issues:

```ldap
(&(servicePrincipalName=*)(!(&(objectClass=computer)(servicePrincipalName=*))))
```

- **Explanation:**
  - Excludes computer accounts to focus on user accounts with SPNs.

---

## Computers

### List All Computers

Retrieve all computer accounts in the domain:

```ldap
(objectCategory=computer)
```

### List Computers Running a Specific Operating System

For example, to find all computers running Windows Server 2019:

```ldap
(&(objectCategory=computer)(operatingSystem=Windows Server 2019*))
```

- **Explanation:**
  - `(operatingSystem=Windows Server 2019*)`: Filters computers with OS starting with "Windows Server 2019".

**Operating System Filters:**

- Windows Server 2022: `Windows Server 2022*`
- Windows 11: `Windows 11*`
- Windows 10: `Windows 10*`

### Find All Workstations

Workstations are computers intended for end-users:

```ldap
(sAMAccountType=805306369)
```

- **Explanation:**
  - `sAMAccountType=805306369`: Corresponds to workstations or member servers.

### Find Computers with `KeyCredentialLink` Attribute

This attribute can be associated with shadow credentials:

```ldap
(&(objectClass=computer)(msDS-KeyCredentialLink=*))
```

### Find Computers with Obsolete Operating Systems

Identifying outdated systems is crucial for security:

```ldap
(&(objectCategory=computer)(|(operatingSystem=Windows XP*)(operatingSystem=Windows Vista*)(operatingSystem=Windows 7*)))
```

- **Explanation:**
  - Filters computers running Windows XP, Vista, or 7.

**Extended Example:**

To include obsolete server OS versions:

```ldap
(&(objectCategory=computer)(|(operatingSystem=Windows NT*)(operatingSystem=Windows 2000*)(operatingSystem=Windows Server 2003*)(operatingSystem=Windows Server 2008*)))
```

---

## Advanced Queries

### Find All Domain Admins

To list all members of the Domain Admins group, including nested group members:

```ldap
(memberOf:1.2.840.113556.1.4.1941:=cn=Domain Admins,cn=Users,dc=hacker26,dc=com)
```

- **Explanation:**
  - Uses `LDAP_MATCHING_RULE_TRANSITIVE_EVAL` to recursively search group memberships.

### Find Users with Password Never Expires

Users with passwords that never expire can be a security risk:

```ldap
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))
```

- **Explanation:**
  - The `65536` flag corresponds to `DONT_EXPIRE_PASSWORD`.

### Find Disabled Computer Accounts

```ldap
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=2))
```

- **Explanation:**
  - The `2` flag corresponds to `ACCOUNTDISABLE`.

---

## Tools for Executing LDAP Queries

Several tools can execute LDAP queries against Active Directory:

- **ldapsearch:** A command-line tool available on Linux and Windows via OpenLDAP.

  **Example:**

  ```bash
  ldapsearch -x -H ldap://domaincontroller.example.com -D "user@example.com" -W -b "dc=hacker26,dc=com" "(objectCategory=person)"
  ```

- **PowerShell:** Use the `Get-ADUser`, `Get-ADGroup`, and `Get-ADComputer` cmdlets.

  **Example:**

  ```powershell
  Get-ADUser -Filter * -Properties *
  ```

- **AD Explorer:** A GUI tool for browsing Active Directory.

---

## Additional References

- [Microsoft Docs: LDAP Query Basics](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)
- [Understanding User Account Control Flags](https://support.microsoft.com/en-us/topic/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-properties-1b4707aa-9cd5-4f52-9c64-a67b6ceb1c8f)
- [MS-DRSR Documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ed5db046-d9f7-4da4-884c-e14b6bcf5471)
- [Active Directory Security: LDAP Syntax Filters](https://adsecurity.org/?p=1275)

