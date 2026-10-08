# Stage 1: Build production static React assets
FROM node:20-alpine AS build-stage

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --include=optional

COPY . .
RUN npm run build

# Stage 2: Serve static production assets via minimal Nginx web server
FROM nginx:1.25-alpine AS production-stage

COPY --from=build-stage /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
