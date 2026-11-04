import { Module } from '@nestjs/common';
import { DiscoveryModule } from '@nestjs/core';
import { PermissionEvaluatorService } from './services/permission-evaluator.service.js';
import { RoutePolicyScanner } from './services/route-policy.scanner.js';

@Module({
  imports: [DiscoveryModule],
  providers: [PermissionEvaluatorService, RoutePolicyScanner],
  exports: [PermissionEvaluatorService, RoutePolicyScanner],
})
export class AuthzModule {}
