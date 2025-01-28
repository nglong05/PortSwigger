## Exploiting static extension cache rules

Cache rules often target static resources by matching common file extensions like .css or .js. This is the default behavior in most CDNs.

If there are discrepancies in how the cache and origin server map the URL path to resources or use delimiters, an attacker may be able to craft a request for a dynamic resource with a static extension that is ignored by the origin server but viewed by the cache.
## Path mapping discrepancies

URL path mapping is the process of associating URL paths with resources on a server, such as files, scripts, or command executions. There are a range of different mapping styles used by different frameworks and technologies. Two common styles are traditional URL mapping and RESTful URL mapping.

Traditional URL mapping represents a direct path to a resource located on the file system. Here's a typical example:

`http://example.com/path/in/filesystem/resource.html`

-    http://example.com points to the server.
-    /path/in/filesystem/ represents the directory path in the server's file system.
-    resource.html is the specific file being accessed.

In contrast, REST-style URLs don't directly match the physical file structure. They abstract file paths into logical parts of the API:

`http://example.com/path/resource/param1/param2`

-    http://example.com points to the server.
-    /path/resource/ is an endpoint representing a resource.
-    param1 and param2 are path parameters used by the server to process the request.

### Exploiting path mapping discrepancies

To test how the origin server maps the URL path to resources, add an arbitrary path segment to the URL of your target endpoint. If the response still contains the same sensitive data as the base response, it indicates that the origin server abstracts the URL path and ignores the added segment. For example, this is the case if modifying /api/orders/123 to /api/orders/123/foo still returns order information.

To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. For example, update /api/orders/123/foo to /api/orders/123/foo.js. If the response is cached, this indicates:

-    That the cache interprets the full URL path with the static extension.
-    That there is a cache rule to store responses for requests ending in .js.

Caches may have rules based on specific static extensions. Try a range of extensions, including .css, .ico, and .exe.

You can then craft a URL that returns a dynamic response that is stored in the cache. Note that this attack is limited to the specific endpoint that you tested, as the origin server often has different abstraction rules for different endpoints. 
### Lab: Exploiting path mapping for web cache deception
To solve the lab, find the API key for the user carlos. You can log in to your own account using the following credentials: wiener:peter. 

The origin server is designed to interpret paths like `/my-account/abc` as if they were `/my-account`

Append a static file extension like `.js`, send the request. Check the headers for: X-Cache: miss
Resend the same request within 30 seconds. Confirm the X-Cache header changes to hit, indicating it was served from the cache.

Create a crafted script in the Body section to make the victim navigate to the malicious URL:

`<script>document.location="https://ID.web-security-academy.net/my-account/abc.js"</script>`