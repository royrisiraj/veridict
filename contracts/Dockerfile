FROM node:24-bookworm-slim
WORKDIR /app/contracts
COPY contracts/package*.json ./
RUN npm ci
COPY contracts/ ./
RUN npx hardhat compile
CMD ["npm", "run", "node"]
