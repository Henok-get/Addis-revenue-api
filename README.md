token request

 curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "app123",
    "client_secret": "secret456",
	"scope":"Unified_Outgoing"
  }'

  query request

  curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJhcHAxMjMiLCJzY29wZSI6IlVuaWZpZWRfT3V0Z29pbmciLCJpYXQiOjE3NDE4Njk0MDksImV4cCI6MTc0MTg3MzAwOX0.QhIEUqgKfYnipIymcEmg4aW2ji7URTYeFucbq80CFPw" \
  -H "X-Basic-Auth:dXNlcjE6cGFzczEyMw=="
