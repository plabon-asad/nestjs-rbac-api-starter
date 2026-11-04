import 'dotenv/config';
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module.js';
import { loadAppEnv } from './config/app.config.js';
import { setupOpenApi } from './config/openapi.js';

async function bootstrap(): Promise<void> {
  const env = loadAppEnv();
  const app = await NestFactory.create(AppModule);

  app.use(helmet());
  app.use(cookieParser());
  app.setGlobalPrefix('api');
  app.enableShutdownHooks();

  // parseEnv refuses to boot production with docs enabled; the flag check stays explicit anyway.
  if (env.docsEnabled) {
    setupOpenApi(app);
  }

  if (!env.isProduction) {
    app.enableCors({ origin: true, credentials: true });
  }

  await app.listen(env.port);
  console.log(`API listening on :${env.port} (provider: ${env.database.provider})`);
}

void bootstrap();
