FROM node:22.18-alpine
WORKDIR /app
COPY --chown=node:node package.json openapi.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node data ./data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["node", "src/main.js", "healthcheck"]
CMD ["node", "src/main.js"]
