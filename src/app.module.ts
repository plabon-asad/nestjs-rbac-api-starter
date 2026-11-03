import { Module } from '@nestjs/common';
import { CoreModule } from './config/core.module.js';

@Module({
  imports: [CoreModule],
})
export class AppModule {}
