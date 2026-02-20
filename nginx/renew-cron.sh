#!/usr/bin/env bash
set -e

NGINX_WORK_DIR="/opt/nginx"

sudo docker run -it --rm --name certbot-renew \
    -v ${NGINX_WORK_DIR}/conf.d:/etc/nginx/conf.d:ro \
    -v ${NGINX_WORK_DIR}/certbot/conf:/etc/letsencrypt:rw \
    -v ${NGINX_WORK_DIR}/certbot/www:/var/www/certbot:rw \
    -v ${NGINX_WORK_DIR}/certbot/cf-api-token.ini:/root/cf-api-token.ini:ro \
    certbot/dns-cloudflare:latest \
    renew -q


sudo docker compose -f ${NGINX_WORK_DIR}/docker-compose.yml exec -T nginx nginx -s reload
# sudo docker compose -f ${NGINX_WORK_DIR}/docker-compose.yml up -d --force-recreate

# sudo crontab -l
# sudo crontab -e
# 0 3 10 * * /opt/nginx/renew-cron.sh >> /var/log/certbot-renew.log 2>&1