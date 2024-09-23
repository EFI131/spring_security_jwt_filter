Seperated jwt logic as following: 
  1. jwt authentication remains in the JwtFilter
  2. access and refresh creation is done in a "post" authentication filter
  3. added a "/refresh" path that accepts a refresh token in a cookie and returns a new access token
