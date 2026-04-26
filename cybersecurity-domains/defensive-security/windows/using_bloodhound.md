# Advanced BloodHound Queries Collection

This document contains a comprehensive collection of queries for use with BloodHound, organized by category. These queries can help you analyze Active Directory environments more effectively.

## User and Group Analysis

### Find all edges any owned user has on a computer
```
MATCH p=shortestPath((m:User)-[r]->(b:Computer)) WHERE m.owned RETURN p
```

### Find all Kerberoastable Users
```
MATCH (n:User) WHERE n.hasspn=true RETURN n
```

### Find Kerberoastable Users with passwords last set > 5 years ago
```
MATCH (u:User) 
WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) 
  AND NOT u.pwdlastset IN [-1.0, 0.0]
RETURN u.name, u.pwdlastset 
ORDER BY u.pwdlastset
```

### Find users that logged in within the last 90 days
```
MATCH (u:User) 
WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) 
  AND NOT u.lastlogon IN [-1.0, 0.0] 
RETURN u.name, u.lastlogon 
ORDER BY u.lastlogon
```

### List users and their login times + password last set times in human-readable format
```
MATCH (n:User) 
WHERE n.enabled = TRUE 
RETURN n.name, 
  datetime({epochSeconds: toInteger(n.pwdlastset)}) as PwdLastSet, 
  datetime({epochSeconds: toInteger(n.lastlogon)}) as LastLogon 
ORDER BY n.pwdlastset
```

### Find users that have never logged on and account is still active
```
MATCH (n:User) 
WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE 
RETURN n.name 
ORDER BY n.name
```

## Computer and Session Analysis

### Find computers with unconstrained delegation that AREN'T domain controllers
```
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) 
WHERE g.objectsid ENDS WITH '-516' 
WITH COLLECT(c1.name) AS domainControllers 
MATCH (c2:Computer {unconstraineddelegation:true}) 
WHERE NOT c2.name IN domainControllers 
RETURN c2.name, c2.operatingsystem 
ORDER BY c2.name ASC
```

### Find active Domain Admin sessions
```
MATCH (n:User)-[:MemberOf*1..]->(g:Group) 
WHERE g.objectid ENDS WITH '-512' 
MATCH p = (c:Computer)-[:HasSession]->(n) 
RETURN p
```

### Find computers with descriptions
```
MATCH (c:Computer) 
WHERE c.description IS NOT NULL 
RETURN c.name, c.description
```

## Domain and Forest Analysis

### Find connections between different domains/forests
```
MATCH (n)-[r]->(m) 
WHERE NOT n.domain = m.domain 
RETURN LABELS(n)[0], n.name, TYPE(r), LABELS(m)[0], m.name
```

## Privilege and Access Analysis

### Find the percentage of computers with a path to Domain Admins
```
MATCH (totalComputers:Computer {domain:'DOMAIN.GR'}) 
MATCH p=shortestPath((ComputersWithPath:Computer {domain:'DOMAIN.GR'})-[r*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.GR'})) 
WITH COUNT(DISTINCT(totalComputers)) as totalComputers, COUNT(DISTINCT(ComputersWithPath)) as ComputersWithPath 
RETURN 100.0 * ComputersWithPath / totalComputers AS percentComputersToDA
```

### Find the most privileged groups on the domain
```
MATCH (g:Group) 
OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer) 
OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) 
WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar 
UNWIND tempVar AS computers 
RETURN g.name AS GroupName, COUNT(DISTINCT(computers)) AS AdminRightCount 
ORDER BY AdminRightCount DESC
```

## Kerberos and Delegation Analysis

### Find users with constrained delegation permissions
```
MATCH (u:User) 
WHERE u.allowedtodelegate IS NOT NULL 
RETURN u.name, u.allowedtodelegate
```

### Find computers with constrained delegation permissions
```
MATCH (c:Computer) 
WHERE c.allowedtodelegate IS NOT NULL 
RETURN c.name, c.allowedtodelegate
```

## GPO and OU Analysis

### View OUs based on member count
```
MATCH (o:OU)-[:Contains]->(c:Computer) 
RETURN o.name, o.guid, COUNT(c) 
ORDER BY COUNT(c) DESC
```

### Find if any domain user has interesting permissions against a GPO
```
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) 
RETURN p 
LIMIT 25
```

## ACL and Permission Analysis

### Find what permissions Everyone/Authenticated Users/Domain Users/Domain Computers have
```
MATCH p=(m:Group)-[r:AddMember|AdminTo|AllExtendedRights|AllowedToDelegate|CanRDP|Contains|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|GetChanges|GetChangesAll|HasSession|Owns|ReadLAPSPassword|SQLAdmin|TrustedBy|WriteDACL|WriteOwner|AddAllowedToAct|AllowedToAct]->(t) 
WHERE m.objectsid ENDS WITH '-513' OR m.objectsid ENDS WITH '-515' OR m.objectsid ENDS WITH 'S-1-5-11' OR m.objectsid ENDS WITH 'S-1-1-0' 
RETURN m.name, TYPE(r), t.name, t.enabled
```

## Miscellaneous Queries

### Adjust Query to Local Timezone (Change timezone parameter)
```
MATCH (u:User) 
WHERE NOT u.lastlogon IN [-1.0, 0.0] 
RETURN u.name, datetime({epochSeconds:toInteger(u.lastlogon), timezone: '+10:00'}) as LastLogon
```

### Find users that are part of the VPN group
```
MATCH (u:User)-[:MemberOf]->(g:Group) 
WHERE g.name CONTAINS "VPN" 
RETURN u.name, g.name
```

