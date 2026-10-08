# PolyShield AI — Production TLS & Reverse Proxy Guide

## 1. TLS Termination Strategy

In production deployments, **TLS termination MUST take place at the edge reverse proxy layer** (e.g., Nginx, HAProxy, AWS ALB, or Traefik) before traffic enters the container network.

```text
HTTPS (Port 443)  --->  [Edge TLS Proxy]  ---> HTTP (Port 80) ---> [PolyShield Nginx / FastAPI]
(Strict TLS 1.3 / HSTS)   (Certbot / Acme)       (Internal Container Net)
```

---

## 2. Nginx Certbot SSL Configuration Template

```nginx
server {
    listen 80;
    server_name polyshield.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name polyshield.example.com;

    ssl_certificate /etc/letsencrypt/live/polyshield.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/polyshield.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HTTP Strict Transport Security (HSTS)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:80; # Directs to PolyShield Nginx Edge
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

---

## 3. Trusted Proxy Configuration

To prevent client spoofing of `X-Forwarded-For` headers, FastAPI applications must only trust forwarded headers from explicit reverse proxy IP addresses or container bridge CIDRs.

- Default Proxy Trust: Isolated internal container bridge (`172.16.0.0/12`).
- Public Direct Access: Disallowed (FastAPI backend must NOT be exposed to raw Internet traffic without proxy headers).
