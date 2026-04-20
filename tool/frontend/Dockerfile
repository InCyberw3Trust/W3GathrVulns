# ── Build ──────────────────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json ./
RUN npm install

COPY index.html vite.config.js ./
COPY public/ ./public/
COPY src/ ./src/

RUN npm run build

# ── Serve ──────────────────────────────────────────────────────
FROM nginx:alpine

# Copie l'app buildée
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod -R 755 /usr/share/nginx/html

# Copie la conf nginx HTTPS
COPY nginx.conf /etc/nginx/conf.d/default.conf

# nginx écoute sur 80 (redirect) et 443 (HTTPS)
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
