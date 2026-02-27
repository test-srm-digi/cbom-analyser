FROM node:20-alpine AS build

WORKDIR /app

# Accept build args for private registries
ARG FONTAWESOME_TOKEN
ARG GH_NPM_TOKEN

COPY .npmrc package*.json ./
RUN npm install --ignore-scripts --legacy-peer-deps

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
