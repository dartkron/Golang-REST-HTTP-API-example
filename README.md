# REST API example

Service have configuration file, which containts: 
- port for service listen
- addresses of Cassandra servers
- Keyspace name. If such keyspace is absent, application will create new one with necessary tables.

External dependency: http://github.com/gocql/gocq

Logs will write to stdout.

Summary application have two methods: /user/ and /session.


## Method /user/

/user/ method realizing create user functionality. Accepting POST request with JSON structure like: { "username": "login", "password": "secret_password" } and initializing adding such user to database. GET/PUT/DELETE and other request types will be ignored with "400 - Bad request" response.

Method generate following responses:

201 - Created -- when requested user created

400 - Bad request -- if had and error in JSON parsing, username is empty, password is empty or request in not POST.

409 - Conflict -- if user with such username was already created.

500 - Internal server error -- if errors happened on connection to database or proceeding CQL requests.



## Method /session/

Accepting POST, GET or DELETE requests.

#### POST

Creating new session. Accepting JSON structure like { "username": "login", "password": "secret_password" }. Generating following responses:

201 - Created -- if session created successfully. Also adding "Set-Cookie: session_id=<long session_id>;" header to response. Cookie expire in one year, same TTL set to record in sessions table in Cassandra.

400 - Bad request -- if had and error in JSON parsing, username is empty, password is empty or request in not POST, GET or DELETE.

401 - Unathorized -- if username or password is invalid.

500 - Internal server error -- if errors happened on connection to database or proceeding CQL requests.


#### GET 

Checking session authorizing. Analyzing cookie session_id and verifying validity. Responding with following codes:

200 - OK -- if session_id cookie from request header is valid

401 - Unathorized -- if session_id cookie in header invalid or absent.

500 - Internal server error -- if errors happened on connection to database or proceeding CQL requests.


#### DELETE 

Deleting session indicated in cookie session_id. Responding with following codes:

200 - OK -- if session deleted successfully. If session_id cookie was absent, also response code is 200.

401 - Unauthorized -- if provided session_id is not valid.

500 - Internal server error -- if errors happened on connection to database or proceeding CQL requests.



## Database structure

Two tables: 

TABLE users (
    username text,
    password text,
    PRIMARY KEY (username, password)
)

and 

TABLE sessions (
    session_id text PRIMARY KEY,
    username text
)


First contain users info, second keeps sessions.
