import { Module, Global } from '@nestjs/common';
import { APP_ENV, loadAppEnv } from './app.config.js';
import { PrismaService } from '../database/prisma/prisma.service.js';
import type { AppEnvironment } from './env.validation.js';

@Global()
@Module({
  providers: [
    {
      provide: APP_ENV,
      useFactory: () => loadAppEnv(),
    },
    {
      provide: PrismaService,
      useFactory: (env: AppEnvironment) => new PrismaService(env),
      inject: [APP_ENV],
    },
  ],
  exports: [APP_ENV, PrismaService],
})
export class CoreModule {}
