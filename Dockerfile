FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./server.js
COPY public ./public

RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 10000
CMD ["npm", "start"]
