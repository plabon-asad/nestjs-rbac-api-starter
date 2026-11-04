# syntax=docker/dockerfile:1

# The Prisma client is generated from one dialect schema at build time, so each image
# serves exactly one provider. Build per target:
#   docker build --build-arg DATABASE_PROVIDER=mysql -t rbac-api:mysql .
# The runtime DATABASE_PROVIDER env var must match the build arg.

FROM node:22-slim AS build
WORKDIR /app
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY prisma.config.ts tsconfig.json tsconfig.build.json nest-cli.json ./
COPY prisma ./prisma
COPY src ./src

ARG DATABASE_PROVIDER=postgresql
# prisma.config.ts resolves env('DATABASE_URL'); generate never connects, so a placeholder fits.
ENV DATABASE_URL=postgresql://placeholder:placeholder@localhost:5432/placeholder
RUN DATABASE_PROVIDER="$DATABASE_PROVIDER" pnpm prisma:generate \
  && pnpm build \
  && pnpm prune --prod

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app

# Runtime holds only production dependencies and the compiled app.
# Database migrations are a release step run outside the container
# (from the repo or CI, before traffic switches to the new image): pnpm db:deploy
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./
COPY --from=build /app/dist ./dist

EXPOSE 3000
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "const net=require('net');const s=net.connect(Number(process.env.PORT||3000),'127.0.0.1');s.on('connect',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));"

CMD ["node", "dist/main.js"]
