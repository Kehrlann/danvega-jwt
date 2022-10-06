# Notes

## POST-based token exchange

- Disable sessions again
- Instead of creating a _controller_ for producing tokens, create a Filter
- Reuse the one that is used for FormLogin: `UsernamePasswordAuthenticationFilter`
- This filter supports POST-based authentication
- On success, it returns the token
- Note: HTTP basic still works, but protects the `/token` endpoint. You would have to jump through many hoops to get
  both working on the same HTTP endpoint

Usage:

```shell
# show that /login works
curl -X POST localhost:8080/login -d"username=dvega" -d"password=password"
# -> returns the token

# On the /token endpoint, httpbasic still works
curl -X POST -u "dvega:password" localhost:8080/token
```
