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

## File Upload Vulnerabilities

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Remote code execution via web shell upload                                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-remote-code-execution-via-web-shell-upload)       |
| Apprentice       | Web shell upload via Content-Type restriction bypass                                         | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-web-shell-upload-via-content-type-restriction-bypass)       |
| Practitioner     | Web shell upload via path traversal                                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-web-shell-upload-via-path-traversal)       |
| Practitioner     | Web shell upload via extension blacklist bypass                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-web-shell-upload-via-extension-blacklist-bypass)       |
| Practitioner     | Web shell upload via obfuscated file extension                                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-web-shell-upload-via-obfuscated-file-extension)       |
| Practitioner     | Remote code execution via polyglot web shell upload                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-remote-code-execution-via-polyglot-web-shell-upload)       |
| Expert           | Web shell upload via race condition                                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/File%20Upload%20Vulnerabilities.md#lab-web-shell-upload-via-race-condition)       |

## JWT

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | JWT authentication bypass via unverified signature                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-unverified-signature)       |
| Apprentice       | JWT authentication bypass via flawed signature verification                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-flawed-signature-verification)       |
| Practitioner     | JWT authentication bypass via weak signing key                                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-weak-signing-key)       |
| Practitioner     | JWT authentication bypass via jwk header injection                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-jwk-header-injection)       |
| Practitioner     | JWT authentication bypass via jku header injection                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-jku-header-injection)       |
| Practitioner     | JWT authentication bypass via kid header path traversal                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-kid-header-path-traversal)       |
| Expert           | JWT authentication bypass via algorithm confusion                                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-algorithm-confusion)       |
| Expert           | JWT authentication bypass via algorithm confusion with no exposed key                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/JWT.md#lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key)       |

## NoSQL Injection

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Detecting NoSQL injection                                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/NoSQL%20Injection.md#lab-detecting-nosql-injection)       |
| Apprentice       | Exploiting NoSQL operator injection to bypass authentication                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/NoSQL%20Injection.md#lab-exploiting-nosql-operator-injection-to-bypass-authentication)       |
| Practitioner     | Exploiting NoSQL injection to extract data                                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/NoSQL%20Injection.md#lab-exploiting-nosql-injection-to-extract-data)       |
| Practitioner     | Exploiting NoSQL operator injection to extract unknown fields                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/NoSQL%20Injection.md#lab-exploiting-nosql-operator-injection-to-extract-unknown-fields)       |

## Insecure Deserialization

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Modifying serialized objects                                                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-modifying-serialized-objects)       |
| Practitioner     | Modifying serialized data types                                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-modifying-serialized-data-types)       |
| Practitioner     | Using application functionality to exploit insecure deserialization                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-using-application-functionality-to-exploit-insecure-deserialization)       |
| Practitioner     | Arbitrary object injection in PHP                                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-arbitrary-object-injection-in-php)       |
| Practitioner     | Exploiting Java deserialization with Apache Commons                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-exploiting-java-deserialization-with-apache-commons)       |
| Practitioner     | Exploiting PHP deserialization with a pre-built gadget chain                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-exploiting-php-deserialization-with-a-pre-built-gadget-chain)       |
| Practitioner     | Exploiting Ruby deserialization using a documented gadget chain                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-exploiting-ruby-deserialization-using-a-documented-gadget-chain)       |
| Expert           | Developing a custom gadget chain for Java deserialization                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-developing-a-custom-gadget-chain-for-java-deserialization)       |
| Expert           | Developing a custom gadget chain for PHP deserialization                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-developing-a-custom-gadget-chain-for-php-deserialization)       |
| Expert           | Using PHAR deserialization to deploy a custom gadget chain                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Insecure%20Deserialization.md#lab-using-phar-deserialization-to-deploy-a-custom-gadget-chain)       |
## Authentication

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Username enumeration via different responses                                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-username-enumeration-via-different-responses)       |
| Apprentice       | 2FA simple bypass                                                                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-2fa-simple-bypass)       |
| Apprentice       | Password reset broken logic                                                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-password-reset-broken-logic)       |
| Practitioner     | Username enumeration via subtly different responses                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-username-enumeration-via-subtly-different-responses)       |
| Practitioner     | Username enumeration via response timing                                                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-username-enumeration-via-response-timing)       |
| Practitioner     | Broken brute-force protection, IP block                                                      | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-broken-brute-force-protection-ip-block)       |
| Practitioner     | Username enumeration via account lock                                                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-username-enumeration-via-account-lock)       |
| Practitioner     | 2FA broken logic                                                                             | Not solved       |
| Practitioner     | Brute-forcing a stay-logged-in cookie                                                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-brute-forcing-a-stay-logged-in-cookie)       |
| Practitioner     | Offline password cracking                                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-offline-password-cracking)       |
| Practitioner     | Password reset poisoning via middleware                                                      | Not solved       |
| Practitioner     | Password brute-force via password change                                                     | Not solved       |
| Expert           | Broken brute-force protection, multiple credentials per request                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Authentication.md#lab-broken-brute-force-protection-multiple-credentials-per-request)       |
| Expert           | 2FA bypass using a brute-force attack                                                        | Not solved       |

## Business Logic Vulnerabilities

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Excessive trust in client-side controls                                                       | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-excessive-trust-in-client-side-controls) |
| Apprentice       | High-level logic vulnerability                                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-high-level-logic-vulnerability) |
| Apprentice       | Inconsistent security controls                                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-inconsistent-security-controls) |
| Apprentice       | Flawed enforcement of business rules                                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-flawed-enforcement-of-business-rules) |
| Practitioner     | Low-level logic flaw                                                                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-low-level-logic-flaw) |
| Practitioner     | Inconsistent handling of exceptional input                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-inconsistent-handling-of-exceptional-input) |
| Practitioner     | Weak isolation on dual-use endpoint                                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-weak-isolation-on-dual-use-endpoint) |
| Practitioner     | Insufficient workflow validation                                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-insufficient-workflow-validation) |
| Practitioner     | Authentication bypass via flawed state machine                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Business%20Logic%20Vulnerabilities.md#lab-authentication-bypass-via-flawed-state-machine) |
| Practitioner     | Infinite money logic flaw                                                                     | Not solved |
| Practitioner     | Authentication bypass via encryption oracle                                                   | Not solved |
| Expert           | Bypassing access controls using email address parsing discrepancies                           | Not solved |

## Race Conditions

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Limit overrun race conditions                                                                 | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Race%20Conditions.md#lab-limit-overrun-race-conditions) |
| Practitioner     | Bypassing rate limits via race conditions                                                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Race%20Conditions.md#lab-bypassing-rate-limits-via-race-conditions) |
| Practitioner     | Multi-endpoint race conditions                                                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Race%20Conditions.md#lab-multi-endpoint-race-conditions) |
| Practitioner     | Single-endpoint race conditions                                                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Race%20Conditions.md#lab-single-endpoint-race-conditions) |
| Practitioner     | Exploiting time-sensitive vulnerabilities                                                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Race%20Conditions.md#lab-exploiting-time-sensitive-vulnerabilities) |
| Expert           | Partial construction race conditions                                                          | Not solved |

## Server-side request forgery (SSRF)

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Basic SSRF against the local server                                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-basic-ssrf-against-the-local-server) |
| Apprentice       | Basic SSRF against another back-end system                                                    | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-basic-ssrf-against-another-back-end-system) |
| Practitioner     | Blind SSRF with out-of-band detection                                                         | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-blind-ssrf-with-out-of-band-detection) |
| Practitioner     | SSRF with blacklist-based input filter                                                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-ssrf-with-blacklist-based-input-filter) |
| Practitioner     | SSRF with filter bypass via open redirection vulnerability                                    | Not solved |
| Expert           | Blind SSRF with Shellshock exploitation                                                       | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-blind-ssrf-with-shellshock-exploitation) |
| Expert           | SSRF with whitelist-based input filter                                                        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/SSRF.md#lab-ssrf-with-whitelist-based-input-filter) |

## API Testing

| **Difficulty**   | **Title**                                                                                     | **Status**   |
|------------------|-----------------------------------------------------------------------------------------------|--------------|
| Apprentice       | Exploiting an API endpoint using documentation | [Solved](https://github.com/nglong05/PortSwigger/blob/main/API%20Testing.md#lab-exploiting-an-api-endpoint-using-documentation) |
| Practitioner     | Exploiting server-side parameter pollution in a query string | [Solved](https://github.com/nglong05/PortSwigger/blob/main/API%20Testing.md#lab-exploiting-server-side-parameter-pollution-in-a-query-string) |
| Practitioner     | Finding and exploiting an unused API endpoint | [Solved](https://github.com/nglong05/PortSwigger/blob/main/API%20Testing.md#lab-finding-and-exploiting-an-unused-api-endpoint) |
| Practitioner     | Exploiting a mass assignment vulnerability | [Solved](https://github.com/nglong05/PortSwigger/blob/main/API%20Testing.md#lab-exploiting-a-mass-assignment-vulnerability) |
| Expert          | Exploiting server-side parameter pollution in a REST URL | [Solved](https://github.com/nglong05/PortSwigger/blob/main/API%20Testing.md#lab-exploiting-server-side-parameter-pollution-in-a-rest-url) |

## Cross-Origin Resource Sharing (CORS)

| **Difficulty**   | **Title**                                                  | **Status**   |
|------------------|------------------------------------------------------------|--------------|
| Apprentice       | CORS vulnerability with basic origin reflection | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CORS.md#lab-cors-vulnerability-with-basic-origin-reflection) |
| Apprentice       | CORS vulnerability with trusted null origin | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CORS.md#lab-cors-vulnerability-with-trusted-null-origin) |
| Practitioner     | CORS vulnerability with trusted insecure protocols | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CORS.md#lab-cors-vulnerability-with-trusted-insecure-protocols) |

## XML External Entity (XXE) Injection

| **Difficulty**   | **Title**                                                                 | **Status**   |
|------------------|---------------------------------------------------------------------------|--------------|
| Apprentice       | Exploiting XXE using external entities to retrieve files                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-xxe-using-external-entities-to-retrieve-files) |
| Apprentice       | Exploiting XXE to perform SSRF attacks                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-xxe-to-perform-ssrf-attacks) |
| Practitioner     | Blind XXE with out-of-band interaction                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-blind-xxe-with-out-of-band-interaction) |
| Practitioner     | Blind XXE with out-of-band interaction via XML parameter entities       | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-blind-xxe-with-out-of-band-interaction-via-xml-parameter-entities) |
| Practitioner     | Exploiting blind XXE to exfiltrate data using a malicious external DTD  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-blind-xxe-to-exfiltrate-data-using-a-malicious-external-dtd) |
| Practitioner     | Exploiting blind XXE to retrieve data via error messages               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-blind-xxe-to-retrieve-data-via-error-messages) |
| Practitioner     | Exploiting XInclude to retrieve files                                  | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-xinclude-to-retrieve-files) |
| Practitioner     | Exploiting XXE via image file upload                                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-xxe-via-image-file-upload) |
| Expert          | Exploiting XXE to retrieve data by repurposing a local DTD             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/XXE.md#lab-exploiting-xxe-to-retrieve-data-by-repurposing-a-local-dtd) |

## DOM-Based Vulnerabilities

| **Difficulty**   | **Title**                                                                 | **Status**   |
|------------------|---------------------------------------------------------------------------|--------------|
| Practitioner     | DOM XSS using web messages                                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/DOM_XSS.md#lab-dom-xss-using-web-messages) |
| Practitioner     | DOM XSS using web messages and a JavaScript URL                         | [Solved](https://github.com/nglong05/PortSwigger/blob/main/DOM_XSS.md#lab-dom-xss-using-web-messages-and-a-javascript-url) |
| Practitioner     | DOM XSS using web messages and JSON.parse                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/DOM_XSS.md#lab-dom-xss-using-web-messages-and-jsonparse) |
| Practitioner     | DOM-based open redirection                                              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/DOM_XSS.md#lab-dom-based-open-redirection) |
| Practitioner     | DOM-based cookie manipulation                                           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/DOM_XSS.md#lab-dom-based-cookie-manipulation) |
| Expert          | Exploiting DOM clobbering to enable XSS                                  | Not solved |
| Expert          | Clobbering DOM attributes to bypass HTML filters                        | Not solved |

## Cross-Site Request Forgery (CSRF)

| **Difficulty**   | **Title**                                                               | **Status**   |
|------------------|-------------------------------------------------------------------------|--------------|
| Apprentice      | CSRF vulnerability with no defenses                                     | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-vulnerability-with-no-defenses) |
| Practitioner    | CSRF where token validation depends on request method                   | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-where-token-validation-depends-on-request-method) |
| Practitioner    | CSRF where token validation depends on token being present              | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-where-token-validation-depends-on-token-being-present) |
| Practitioner    | CSRF where token is not tied to user session                            | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-where-token-is-not-tied-to-user-session) |
| Practitioner    | CSRF where token is tied to non-session cookie                          | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-where-token-is-tied-to-non-session-cookie) |
| Practitioner    | CSRF where token is duplicated in cookie                               | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-csrf-where-token-is-duplicated-in-cookie) |
| Practitioner    | SameSite Lax bypass via method override                                | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-samesite-lax-bypass-via-method-override) |
| Practitioner    | SameSite Strict bypass via client-side redirect                       | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-samesite-strict-bypass-via-client-side-redirect) |
| Practitioner    | SameSite Strict bypass via sibling domain                             | [Solved](https://github.com/nglong05/PortSwigger/blob/main/CSRF.md#lab-samesite-strict-bypass-via-sibling-domain) |
| Practitioner    | SameSite Lax bypass via cookie refresh                                | Not solved |
| Practitioner    | CSRF where Referer validation depends on header being present         | Not solved |
| Practitioner    | CSRF with broken Referer validation                                   | Not solved |

## Web LLM Attacks

| **Difficulty**   | **Title**                                         | **Status**   |
|------------------|--------------------------------------------------|--------------|
| Apprentice      | Exploiting LLM APIs with excessive agency        | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Web_LLM_Attacks.md#lab-exploiting-llm-apis-with-excessive-agency) |
| Practitioner    | Exploiting vulnerabilities in LLM APIs           | [Solved](https://github.com/nglong05/PortSwigger/blob/main/Web_LLM_Attacks.md#lab-exploiting-vulnerabilities-in-llm-apis) |
| Practitioner    | Indirect prompt injection                        | Not solved |
| Expert         | Exploiting insecure output handling in LLMs       | Not solved |
