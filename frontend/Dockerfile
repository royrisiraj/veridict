FROM node:24-bookworm-slim AS build
RUN npm install --global pnpm@11.24.0
WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build
FROM node:24-bookworm-slim
WORKDIR /app
COPY --from=build /app/frontend/.next/standalone ./
COPY --from=build /app/frontend/.next/static ./.next/static
ENV HOSTNAME=0.0.0.0 PORT=3000
CMD ["node", "server.js"]
