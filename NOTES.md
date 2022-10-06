# Notes

## POST-based token exchange, with a controller

- No sessions, no custom filters
- Create a custom AuthenticationManager-@Bean
  - This will create a global authentication manager in spring-sec terms, exactly the same as if you created just a
    UserDetailsService-@Bean
  - It probably has subtle consequences vs generating a UserDetailsService-@Bean, but can't think about the details top
    off my head. Very likely makes NO difference to user apps.
- Inject that authmanger into the controller
- The controller checks for authentication: if it exists, it came through FormLogin (or from a token)
  - If there's no authentication, it uses the auth manager to auth against the request body
- On success, it returns the token

Usage:

```shell
# show that /token works with a json payload
curl -X POST localhost:8080/token -d'{"username": "dvega", "password": "password"}' -H"Content-Type: application/json"
# -> returns the token

# On the /token endpoint, httpbasic still works
curl -X POST -u "dvega:password" localhost:8080/token
# -> returns the token

# Also, you can use the token to get a token 🤷
TOKEN=$(curl -X POST -u "dvega:password" localhost:8080/token)
curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8080/token
```
