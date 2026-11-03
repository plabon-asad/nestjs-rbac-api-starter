import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { APP_ENV, loadAppEnv } from '../../src/config/app.config.js';
import { CoreModule } from '../../src/config/core.module.js';
import { PrismaService } from '../../src/database/prisma/prisma.service.js';
import { AuthModule } from '../../src/modules/auth/auth.module.js';
import { PermissionsModule } from '../../src/modules/permissions/permissions.module.js';
import { RolesModule } from '../../src/modules/roles/roles.module.js';
import { MailerPort } from '../../src/modules/auth/interfaces/mailer.port.js';
import type { AppEnvironment } from '../../src/config/env.validation.js';
import { prisma } from './prisma-test.js';

export interface SentMail {
  readonly to: string;
  readonly token: string;
  readonly expiresAt: Date;
}

export class CapturingMailer implements MailerPort {
  readonly sent: SentMail[] = [];
  sendPasswordReset(to: string, token: string, expiresAt: Date): Promise<void> {
    this.sent.push({ to, token, expiresAt });
    return Promise.resolve();
  }
}

export function makeTestEnvForApp(): AppEnvironment {
  return loadAppEnv({
    ...process.env,
    NODE_ENV: 'test',
    DATABASE_URL: process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? '',
    AUTH_THROTTLE_LIMIT: '1000',
    AUTH_THROTTLE_TTL_SECONDS: '3600',
  });
}

export interface TestContext {
  readonly app: INestApplication;
  readonly env: AppEnvironment;
  readonly mailer: CapturingMailer;
}

export async function createTestApp(): Promise<TestContext> {
  const env = makeTestEnvForApp();
  const mailer = new CapturingMailer();

  const moduleRef = await Test.createTestingModule({
    imports: [CoreModule, AuthModule, RolesModule, PermissionsModule],
  })
    .overrideProvider(APP_ENV)
    .useValue(env)
    .overrideProvider(PrismaService)
    .useValue(prisma)
    .overrideProvider(MailerPort)
    .useValue(mailer)
    .compile();

  const app = moduleRef.createNestApplication();
  app.use(cookieParser());
  app.setGlobalPrefix('api');
  await app.init();
  return { app, env, mailer };
}
