#!/usr/bin/env bash
set -e

# Nginx config folder (mounted in Certbot container)
NGINX_WORK_DIR="/opt/nginx"
NGINX_CONF_DIR="${NGINX_WORK_DIR}/conf.d"

# Webroot for HTTP-01 challenge (shared volume with Nginx)
CERTBOT_WEBROOT="${NGINX_WORK_DIR}/certbot/www"

for conf_file in "$NGINX_CONF_DIR"/*.conf; do
    server_names=$(grep -E '^\s*server_name' "$conf_file" \
    | sed -E 's/^\s*server_name\s+//;s/;//' \
    | tr ' ' '\n' \
    | sort -u)

    for domain in $server_names; do
        echo "=== Processing domain: $domain ==="

        # Check if certificate already exists
        if [ ! -d "${NGINX_WORK_DIR}/certbot/conf/live/$domain" ]; then
            echo "Requesting certificate for $domain..."
            sudo docker run -it --rm --name certbot \
                -v ${NGINX_WORK_DIR}/conf.d:/etc/nginx/conf.d:rw \
                -v ${NGINX_WORK_DIR}/certbot/conf:/etc/letsencrypt:rw \
                -v ${NGINX_WORK_DIR}/certbot/www:/var/www/certbot/:rw \
                -v ${NGINX_WORK_DIR}/certbot/cf-api-token.ini:/root/cf-api-token.ini:rw \
                certbot/dns-cloudflare:latest \
                certonly -d "$domain" \
                --dns-cloudflare \
                --dns-cloudflare-propagation-seconds 60 \
                --dns-cloudflare-credentials /root/cf-api-token.ini\
                --non-interactive --agree-tos

             sudo docker compose -f ${NGINX_WORK_DIR}/docker-compose.yml exec -T nginx nginx -s reload
            # sudo docker compose -f ${NGINX_WORK_DIR}/docker-compose.yml up -d --force-recreate
        else
            echo "Certificate for $domain already exists, skipping."
        fi
    done
done