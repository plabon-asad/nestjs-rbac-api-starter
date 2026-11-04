import { Injectable, RequestMethod, type OnApplicationBootstrap } from '@nestjs/common';
import { PATH_METADATA, METHOD_METADATA } from '@nestjs/common/constants';
import { DiscoveryService, Reflector } from '@nestjs/core';
import { AUTHENTICATED_ONLY_KEY } from '../../../common/decorators/authenticated-only.decorator.js';
import { IS_PUBLIC_KEY } from '../../../common/decorators/public.decorator.js';
import { REQUIRE_PERMISSIONS_KEY } from '../../../common/decorators/require-permissions.decorator.js';

/** Reflector declares its targets as `Type<any> | Function`; handler methods satisfy this shape. */
type Handler = () => unknown;
type ReflectTarget = NonNullable<
  ReturnType<DiscoveryService['getControllers']>[number]['metatype']
>;

/**
 * Deny-by-default, enforced at boot. Every HTTP handler must declare exactly one policy:
 * `@Public()`, `@AuthenticatedOnly()` or `@RequirePermissions()`. Anything else throws before
 * the process starts listening, so a route added in a hurry cannot silently ship unprotected.
 * Paths in the message are handler paths and exclude the global `api` prefix.
 */
@Injectable()
export class RoutePolicyScanner implements OnApplicationBootstrap {
  constructor(
    private readonly reflector: Reflector,
    private readonly discovery: DiscoveryService,
  ) {}

  onApplicationBootstrap(): void {
    const violations = this.findViolations();
    if (violations.length > 0) {
      throw new Error(
        `Deny-by-default violated: ${violations.length} route(s) declare no access policy. ` +
          `Add @Public(), @AuthenticatedOnly() or @RequirePermissions() to:\n- ${violations.join('\n- ')}`,
      );
    }
  }

  findViolations(): string[] {
    const violations: string[] = [];

    for (const controller of this.discovery.getControllers()) {
      const target = controller.metatype;
      if (target === null || target === undefined) {
        continue;
      }
      const prototype = Object.getPrototypeOf(controller.instance as object) as object;
      const basePath = this.reflector.get<string>(PATH_METADATA, target) ?? '';

      for (const handler of this.httpHandlers(prototype)) {
        if (this.hasPolicy(handler.fn, target)) {
          continue;
        }
        const handlerPath = this.reflector.get<string | undefined>(PATH_METADATA, handler.fn);
        violations.push(
          `${this.methodName(handler.verb)} ${this.formatPath(basePath, handlerPath)}`,
        );
      }
    }

    return violations;
  }

  /**
   * Only methods carrying `METHOD_METADATA` are routes; anything else on the prototype
   * (`constructor`, plain helper methods) is skipped.
   */
  private httpHandlers(prototype: object): readonly { fn: Handler; verb: RequestMethod }[] {
    return Object.getOwnPropertyNames(prototype)
      .filter((name) => name !== 'constructor')
      .map((name) => Object.getOwnPropertyDescriptor(prototype, name)?.value as unknown)
      .filter((fn): fn is Handler => typeof fn === 'function')
      .flatMap((fn) => {
        const verb = this.reflector.get<RequestMethod | undefined>(METHOD_METADATA, fn);
        return verb === undefined ? [] : [{ fn, verb }];
      });
  }

  private hasPolicy(handler: Handler, controller: ReflectTarget): boolean {
    const scope: (Handler | ReflectTarget)[] = [handler, controller];
    return (
      this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, scope) === true ||
      this.reflector.getAllAndOverride<boolean>(AUTHENTICATED_ONLY_KEY, scope) === true ||
      this.reflector.getAllAndOverride<object>(REQUIRE_PERMISSIONS_KEY, scope) !== undefined
    );
  }

  private methodName(verb: RequestMethod): string {
    return RequestMethod[verb] ?? 'ALL';
  }

  private formatPath(basePath: string, handlerPath: string | undefined): string {
    const joined = `/${basePath}/${handlerPath ?? '/'}`.replace(/\/{2,}/g, '/');
    return joined.length > 1 ? joined.replace(/\/+$/, '') : joined;
  }
}
