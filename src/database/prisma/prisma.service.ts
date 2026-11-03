import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaMariaDb } from '@prisma/adapter-mariadb';
import { PrismaPg } from '@prisma/adapter-pg';
import type { SqlDriverAdapterFactory } from '@prisma/driver-adapter-utils';
import { PrismaClient } from '../../generated/prisma/client.js';
import type { AppEnvironment } from '../../config/env.validation.js';

function createDriverAdapter(env: AppEnvironment): SqlDriverAdapterFactory {
  if (env.database.provider === 'postgresql') {
    return new PrismaPg({ connectionString: env.database.url });
  }
  return new PrismaMariaDb(env.database.url);
}

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor(env: AppEnvironment) {
    super({ adapter: createDriverAdapter(env) });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
