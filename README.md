## SQL Injection
| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-vulnerability-in-where-clause-allowing-retrieval-of-hidden-data)       |
| Apprentice       | SQL injection vulnerability allowing login bypass                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-vulnerability-allowing-login-bypass)       |
| Practitioner     | SQL injection attack, querying the database type and version on Oracle                        | Not Solved   |
| Practitioner     | SQL injection attack, querying the database type and version on MySQL and Microsoft           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-attack-querying-the-database-type-and-version-on-mysql-and-microsoft)       |
| Practitioner     | SQL injection attack, listing the database contents on non-Oracle databases                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-attack-listing-the-database-contents-on-non-oracle-databases)       |
| Practitioner     | SQL injection attack, listing the database contents on Oracle                                 | Not Solved   |
| Practitioner     | SQL injection UNION attack, determining the number of columns returned by the query           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query)       |
| Practitioner     | SQL injection UNION attack, finding a column containing text                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-union-attack-finding-a-column-containing-text)       |
| Practitioner     | SQL injection UNION attack, retrieving data from other tables                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-union-attack-retrieving-data-from-other-tables)       |
| Practitioner     | SQL injection UNION attack, retrieving multiple values in a single column                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-sql-injection-union-attack-retrieving-multiple-values-in-a-single-column)       |
| Practitioner     | Blind SQL injection with conditional responses                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-blind-sql-injection-with-conditional-responses)       |
| Practitioner     | Blind SQL injection with conditional errors                                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-blind-sql-injection-with-conditional-errors)       |
| Practitioner     | Visible error-based SQL injection                                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SQL%20Injection.md#lab-visible-error-based-sql-injection)       |
| Practitioner     | Blind SQL injection with time delays                                                          | Not Solved   |
| Practitioner     | Blind SQL injection with time delays and information retrieval                                | Not Solved   |
| Practitioner     | Blind SQL injection with out-of-band interaction                                              | Not Solved   |
| Practitioner     | Blind SQL injection with out-of-band data exfiltration                                        | Not Solved   |
| Practitioner     | SQL injection with filter bypass via XML encoding                                             | Not Solved   |

## Path Traversal

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | File path traversal, simple case                                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-simple-case)       |
| Practitioner     | File path traversal, traversal sequences blocked with absolute path bypass                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-traversal-sequences-blocked-with-absolute-path-bypass)       |
| Practitioner     | File path traversal, traversal sequences stripped non-recursively                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-traversal-sequences-stripped-non-recursively)       |
| Practitioner     | File path traversal, traversal sequences stripped with superfluous URL-decode                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-traversal-sequences-stripped-with-superfluous-url-decode)       |
| Practitioner     | File path traversal, validation of start of path                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-validation-of-start-of-path)       |
| Practitioner     | File path traversal, validation of file extension with null byte bypass                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Path%20Traversal.md#lab-file-path-traversal-validation-of-file-extension-with-null-byte-bypass)       |

## Server-side Template Injection

| **Difficulty**   | **Title**                                                                                             | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------------|--------------|
| Practitioner     | Basic server-side template injection                                                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-basic-server-side-template-injection)       |
| Practitioner     | Basic server-side template injection (code context)                                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-basic-server-side-template-injection-code-context)       |
| Practitioner     | Server-side template injection using documentation                                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-server-side-template-injection-using-documentation)       |
| Practitioner     | Server-side template injection in an unknown language with a documented exploit                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)       |
| Practitioner     | Server-side template injection with information disclosure via user-supplied objects                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)       |
| Expert           | Server-side template injection in a sandboxed environment                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSTI.md#lab-server-side-template-injection-in-a-sandboxed-environment)       |
| Expert           | Server-side template injection with a custom exploit                                                 | Not Solved   |

## WebSockets

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Manipulating WebSocket messages to exploit vulnerabilities                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/WebSockets.md#lab-manipulating-websocket-messages-to-exploit-vulnerabilities)       |
| Practitioner     | Cross-site WebSocket hijacking                                                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/WebSockets.md#lab-cross-site-websocket-hijacking)       |
| Practitioner     | Manipulating the WebSocket handshake to exploit vulnerabilities                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/WebSockets.md#lab-manipulating-the-websocket-handshake-to-exploit-vulnerabilities)       |

## Access Control Vulnerabilities

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Unprotected admin functionality                                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-unprotected-admin-functionality)       |
| Apprentice       | Unprotected admin functionality with unpredictable URL                                       | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-unprotected-admin-functionality-with-unpredictable-url)       |
| Apprentice       | User role controlled by request parameter                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-role-controlled-by-request-parameter)       |
| Apprentice       | User role can be modified in user profile                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-role-can-be-modified-in-user-profile)       |
| Apprentice       | User ID controlled by request parameter                                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-id-controlled-by-request-parameter)       |
| Apprentice       | User ID controlled by request parameter, with unpredictable user IDs                         | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)       |
| Apprentice       | User ID controlled by request parameter with data leakage in redirect                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)       |
| Apprentice       | User ID controlled by request parameter with password disclosure                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-user-id-controlled-by-request-parameter-with-password-disclosure)       |
| Apprentice       | Insecure direct object references                                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-insecure-direct-object-references)       |
| Practitioner     | URL-based access control can be circumvented                                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-url-based-access-control-can-be-circumvented)       |
| Practitioner     | Method-based access control can be circumvented                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-method-based-access-control-can-be-circumvented)       |
| Practitioner     | Multi-step process with no access control on one step                                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-multi-step-process-with-no-access-control-on-one-step)       |
| Practitioner     | Referer-based access control                                                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Access%20Control%20Vulnerabilities.md#lab-referer-based-access-control)   |

## Information Disclosure

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Information disclosure in error messages                                                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Information%20Disclosure.md#lab-information-disclosure-in-error-messages)       |
| Apprentice       | Information disclosure on debug page                                                         | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Information%20Disclosure.md#lab-information-disclosure-on-debug-page)       |
| Apprentice       | Source code disclosure via backup files                                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Information%20Disclosure.md#lab-source-code-disclosure-via-backup-files)       |
| Apprentice       | Authentication bypass via information disclosure                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Information%20Disclosure.md#lab-authentication-bypass-via-information-disclosure)       |
| Practitioner     | Information disclosure in version control history                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Information%20Disclosure.md#lab-information-disclosure-in-version-control-history)       |
## OS Command Injection

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | OS command injection, simple case                                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/OS%20Command%20Injection.md#lab-os-command-injection-simple-case)       |
| Practitioner     | Blind OS command injection with time delays                                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/OS%20Command%20Injection.md#lab-blind-os-command-injection-with-time-delays)       |
| Practitioner     | Blind OS command injection with output redirection                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/OS%20Command%20Injection.md#lab-blind-os-command-injection-with-output-redirection)       |
| Practitioner     | Blind OS command injection with out-of-band interaction                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/OS%20Command%20Injection.md#lab-blind-os-command-injection-with-out-of-band-interaction)       |
| Practitioner     | Blind OS command injection with out-of-band data exfiltration                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/OS%20Command%20Injection.md#lab-blind-os-command-injection-with-out-of-band-data-exfiltration)       |


## GraphQL API Vulnerabilities

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Accessing private GraphQL posts                                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/GraphQL%20API%20Vulnerabilities.md#lab-accessing-private-graphql-posts)       |
| Practitioner     | Accidental exposure of private GraphQL fields                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/GraphQL%20API%20Vulnerabilities.md#lab-accidental-exposure-of-private-graphql-fields)       |
| Practitioner     | Finding a hidden GraphQL endpoint                                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/GraphQL%20API%20Vulnerabilities.md#lab-finding-a-hidden-graphql-endpoint)       |
| Practitioner     | Bypassing GraphQL brute force protections                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/GraphQL%20API%20Vulnerabilities.md#lab-bypassing-graphql-brute-force-protections)       |
| Practitioner     | Performing CSRF exploits over GraphQL                                                        | Not Solved   |
