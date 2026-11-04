import { Module } from '@nestjs/common';
import { AuthzModule } from '../authz/authz.module.js';
import { RolesController } from './controllers/roles.controller.js';
import { RolesService } from './services/roles.service.js';

@Module({
  imports: [AuthzModule],
  controllers: [RolesController],
  providers: [RolesService],
  exports: [RolesService],
})
export class RolesModule {}
