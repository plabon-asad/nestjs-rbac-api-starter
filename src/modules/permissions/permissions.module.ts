import { Module } from '@nestjs/common';
import { PermissionsController } from './controllers/permissions.controller.js';
import { PermissionsService } from './services/permissions.service.js';

@Module({
  controllers: [PermissionsController],
  providers: [PermissionsService],
  exports: [PermissionsService],
})
export class PermissionsModule {}
