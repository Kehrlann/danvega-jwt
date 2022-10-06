# Notes

## POST-based login

- Enable `.formLogin(withDefaults())`, this will bootstrap a `UsernamePasswordAuthenticationFilter`
- You _need_ session in order for this to work, because `/login` yields a session cookie
- This filter supports POST-based authentication

Usage:

```shell
# show that /login works
curl -X POST localhost:8080/login -d"username=dvega" -d"password=password" -v

# Get the cookie (nasty sed regexp)
COOKIE=$(curl -X POST localhost:8080/login -d"username=dvega" -d"password=password" -sD- | sed -n "s/Set-Cookie: \(JSESSIONID=[0-9A-Z]*\);.*/\1/p")

# Use the cookie to get a token
TOKEN=$(curl -XPOST localhost:8080/token -b "$COOKIE")

# Use the token
curl localhost:8080/secure -H "Authorization: Bearer $TOKEN"
```

- In this case though, JWT is not super useful since you have sessions for authentication!
