FROM nginx:1.21.6

COPY ngx_http_secure_req_module.so /usr/lib/nginx/modules/ngx_http_secure_req_module.so
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf