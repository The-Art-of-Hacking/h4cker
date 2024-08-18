# Server-Side Request Forgery Prevention Cheat Sheet

## Introduction
The objective of the cheat sheet is to provide advice regarding the protection against Server-Side Request Forgery (SSRF) attacks.

This cheat sheet will focus on the defensive point of view and will not explain how to perform this attack. [This talk](https://www.slideshare.net/OrangeTsai/ssrf-attacks) by security researcher Orange Tsai, as well as [this document](https://docs.google.com/document/d/1V96Uw1VeHGRirvNw9QfZJTrzwLf28yJOl6PMD0SxHRg), provide techniques on how to perform this kind of attack.

## Context
SSRF is an attack vector that abuses an application to interact with the internal/external network or the machine itself. One of the enablers for this vector is the mishandling of URLs, as showcased in the following examples:

- Image on an external server (e.g., user enters image URL of their avatar for the application to download and use).
- Custom WebHook (users have to specify Webhook handlers or Callback URLs).
- Internal requests to interact with another service to serve a specific functionality. Most of the time, user data is sent along to be processed, and if poorly handled, can perform specific injection attacks.

## Overview of a SSRF Common Flow

SSRF Common Flow

**Notes:**

- SSRF is not limited to the HTTP protocol. Generally, the first request is HTTP, but in cases where the application itself performs the second request, it could use different protocols (e.g., FTP, SMB, SMTP, etc.) and schemes (e.g., `file://`, `phar://`, `gopher://`, `data://`, `dict://`, etc.).
- If the application is vulnerable to XML eXternal Entity (XXE) injection, it can be exploited to perform an SSRF attack. Take a look at the [XXE cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) to learn how to prevent exposure to XXE.

## Cases
Depending on the application's functionality and requirements, there are two basic cases in which SSRF can happen:

1. **Application can send requests only to identified and trusted applications**: This occurs when an allowlist approach is available.
2. **Application can send requests to ANY external IP address or domain name**: This occurs when an allowlist approach is unavailable.

Because these two cases are very different, this cheat sheet will describe defenses against them separately.

### Case 1 - Application Can Send Requests Only to Identified and Trusted Applications
Sometimes, an application needs to perform a request to another application, often located on another network, to perform a specific task. Depending on the business case, user input is required for the functionality to work.

#### Example
Take the example of a web application that receives and uses personal information from a user, such as their first name, last name, birth date, etc., to create a profile in an internal HR system. By design, that web application will have to communicate using a protocol that the HR system understands to process that data. Basically, the user cannot reach the HR system directly, but if the web application in charge of receiving user information is vulnerable to SSRF, the user can leverage it to access the HR system. The user leverages the web application as a proxy to the HR system.

The allowlist approach is a viable option since the internal application called by the VulnerableApplication is clearly identified in the technical/business flow. It can be stated that the required calls will only be targeted between those identified and trusted applications.

### Available Protections
Several protective measures are possible at the Application and Network layers. To apply the defense-in-depth principle, both layers will be hardened against such attacks.

#### Application Layer
The first level of protection that comes to mind is **Input validation**.

Based on that point, the following question comes to mind: How to perform this input validation?

As Orange Tsai shows in his talk, depending on the programming language used, parsers can be abused. One possible countermeasure is to apply the allowlist approach when input validation is used because, most of the time, the format of the information expected from the user is globally known.

The request sent to the internal application will be based on the following information:

- String containing business data.
- IP address (V4 or V6).
- Domain name.
- URL.

**Note:** Disable the support for redirection in your web client to prevent bypassing input validation described in the section [Exploitation tricks > Bypassing restrictions > Input validation > Unsafe redirect](#) of this document.

##### String
In the context of SSRF, validations can be added to ensure that the input string respects the business/technical format expected.

A regex can be used to ensure that data received is valid from a security point of view if the input data has a simple format (e.g., token, zip code, etc.). Otherwise, validation should be conducted using the libraries available from the string object because regex for complex formats are difficult to maintain and are highly error-prone.

User input is assumed to be non-network related and consists of the user's personal information.

**Example:**

```java
// Regex validation for data having a simple format
if(Pattern.matches("[a-zA-Z0-9\\s\\-]{1,50}", userInput)){
    // Continue the processing because the input data is valid
} else {
    // Stop the processing and reject the request
}
```
