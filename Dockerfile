# Use Puppeteer's base image so Chrome deps are already installed
FROM ghcr.io/puppeteer/puppeteer:22.12.0

WORKDIR /app

# Install only production deps
COPY package*.json ./
RUN npm ci --omit=dev

# Copy the rest of the code
COPY . .

# Runtime config
ENV NODE_ENV=production
ENV TZ=Asia/Bangkok
ENV PORT=3000
# Point to a writable place for SQLite (we'll mount it)
ENV DB_FILE=/data/data.sqlite

EXPOSE 3000

CMD ["node", "server.js"]