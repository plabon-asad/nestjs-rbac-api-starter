import { Module } from '@nestjs/common';
import { CoreModule } from './config/core.module.js';
import { AuthModule } from './modules/auth/auth.module.js';

@Module({
  imports: [CoreModule, AuthModule],
})
export class AppModule {}
