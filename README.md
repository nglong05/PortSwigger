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
