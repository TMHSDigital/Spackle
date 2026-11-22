FROM node:latest
WORKDIR /srv/app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
ENV SESSION_SECRET=fixture-s3ss10n-8Kd2Pq7Wn4Zx6Ty
EXPOSE 3000
CMD ["node", "server.js"]
