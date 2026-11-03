import { Module } from '@nestjs/common';
import { RolesController } from './controllers/roles.controller.js';
import { RolesService } from './services/roles.service.js';

@Module({
  controllers: [RolesController],
  providers: [RolesService],
  exports: [RolesService],
})
export class RolesModule {}
