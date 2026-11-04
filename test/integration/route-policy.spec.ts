import { Controller, Get, Post, type Type } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { AuthenticatedOnly } from '../../src/common/decorators/authenticated-only.decorator.js';
import { Public } from '../../src/common/decorators/public.decorator.js';
import { RequirePermissions } from '../../src/common/decorators/require-permissions.decorator.js';
import { createTestApp } from '../utils/create-test-app.js';

@Controller('rogue')
class RogueController {
  @Get()
  leak(): { ok: boolean } {
    return { ok: true };
  }
}

@Controller('second-rogue')
class SecondRogueController {
  @Get('nested')
  handler(): { ok: boolean } {
    return { ok: true };
  }
}

@Controller('public-only')
class PublicController {
  @Public()
  @Post('login')
  login(): { ok: boolean } {
    return { ok: true };
  }
}

@Controller('self')
class SelfController {
  @AuthenticatedOnly()
  @Get('me')
  me(): { ok: boolean } {
    return { ok: true };
  }
}

@Controller('guarded')
@RequirePermissions(['roles.read'])
class ClassLevelController {
  @Get()
  list(): { ok: boolean } {
    return { ok: true };
  }

  @Post()
  @RequirePermissions(['roles.create'])
  create(): { ok: boolean } {
    return { ok: true };
  }
}

async function expectInitToThrow(controllers: readonly Type<unknown>[]): Promise<string> {
  try {
    const ctx = await createTestApp({ extraControllers: controllers });
    await ctx.app.close();
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe('deny-by-default route policy scan', () => {
  it('accepts every route the starter itself ships', async () => {
    const ctx = await createTestApp();
    await expect(ctx.app.init()).resolves.toBe(ctx.app);
    await ctx.app.close();
  });

  it('fails startup when a route declares no access policy', async () => {
    expect(await expectInitToThrow([RogueController])).toMatch(/rogue/i);
  });

  it('names every offending route in one pass', async () => {
    const message = await expectInitToThrow([RogueController, SecondRogueController]);

    expect(message).toContain('GET /rogue');
    expect(message).toContain('GET /second-rogue/nested');
  });

  it('accepts routes that opt into public, authenticated-only or permission-protected', async () => {
    const ctx = await createTestApp({
      extraControllers: [PublicController, SelfController, ClassLevelController],
    });
    await expect(ctx.app.init()).resolves.toBe(ctx.app);
    await ctx.app.close();
  });

  it('rejects an empty permission requirement instead of treating it as allow-all', () => {
    expect(() => RequirePermissions([])).toThrow(/at least one/i);
  });
});
