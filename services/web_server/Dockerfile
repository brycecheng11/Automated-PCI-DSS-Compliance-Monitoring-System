FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -days 365 \
        -subj "/CN=web-server"

COPY nginx.conf /etc/nginx/conf.d/default.conf

