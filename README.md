# jitsi-oidc-stack
Minimal stack for deploying Jitsi with OIDC and an Nginx reverse proxy.

## Background
The OIDC adapter was taken from [sheyaln/jitsi-oidc-adapter](https://github.com/sheyaln/jitsi-oidc-adapter)

Please check what has been added and modified in the OIDC authorization (app.py and body.html)
in [sheyaln/jitsi-oidc-adapter](https://github.com/sheyaln/jitsi-oidc-adapter)
and replace them with the latest versions if necessary.

### The setup includes:
- **Nginx container**
- **Minimal Jitsi setup**: Jitsi Web, Prosody (xmpp server), Jicofo (focus component), and JVB (video bridge)
- **OIDC adapter**
- **Creating and renewing certificates using Certbot with a Cloudflare token** (replace the Certbot Image with a Let’s Encrypt one if necessary)


## Configuration
Firewall:
```bash
sudo ufw allow 22/tcp # SSH Port
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 10000/udp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp

sudo ufw disable; sudo ufw enable
sudo ufw status numbered
```

Create a network:
```bash
sudo docker network create proxy
```

Generate passwords and tokens:
```bash
cd jitsi && ./gen-passwords.sh
```
#### Add <your_domain> to:
```
- nginx/conf.d/jitsi.conf
- jitsi/docker-compose.yml
- jitsi/.env
```

Generate a certificate and add the update to cron:
```bash
cd nginx && sudo ./new-certs.sh
sudo crontab -l
sudo crontab -e
0 3 10 * * /opt/nginx/renew-cron.sh >> /var/log/certbot-renew.log 2>&1
```

### Jitsi
Your Jitsi web container needs these env vars to enable JWT auth and point
unauthenticated users at the adapter:
```
ENABLE_AUTH=1
AUTH_TYPE=jwt
JWT_ALLOW_EMPTY=0
TOKEN_AUTH_URL=https://<your_domain>/oidc/auth?room={room}
ENABLE_GUESTS=1
```
In most cases the required values have already been set

### OIDC:

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_CLIENT_ID` | yes | | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | yes | | OAuth2 client secret |
| `OIDC_DISCOVERY_URL` | yes | | OIDC discovery endpoint (`.well-known/openid-configuration`) |
| `OIDC_SCOPE` | no | `openid email profile` | Scopes to request |
| `JITSI_BASE_URL` | yes | | Public URL of your Jitsi instance (e.g. `https://meet.example.com`) |
| `JWT_APP_ID` | no | `jitsi` | Must match Jitsi's `JWT_APP_ID` |
| `JWT_APP_SECRET` | yes | | Must match Jitsi's `JWT_APP_SECRET` |
| `JWT_SUBJECT` | no | `meet.example.com` | JWT `sub` claim, typically your Jitsi domain |
| `LOG_LEVEL` | no | `INFO` | Python log level |

## Running with Docker Compose
```bash
cd jitsi && sudo docker compose up -d --force-recreate --build
```
```bash
cd nginx && sudo docker compose up -d --force-recreate
```

## body.html

The `body.html` file contains JavaScript that intercepts Jitsi's "I am the
host" login dialog and redirects to `/oidc/auth` instead.

## License

Apache License 2.0