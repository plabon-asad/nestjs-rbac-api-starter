import { describe, expect, it } from 'vitest';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';

// Fast parameter set for tests; production defaults are asserted separately.
function testService(): PasswordService {
  return new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });
}

describe('PasswordService', () => {
  it('produces argon2id encoded hashes', async () => {
    const service = testService();
    const hash = await service.hash('correct-horse-battery-staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(hash).not.toContain('correct-horse-battery-staple');
  });

  it('uses random salts so identical passwords hash differently', async () => {
    const service = testService();
    const [a, b] = await Promise.all([
      service.hash('same-password'),
      service.hash('same-password'),
    ]);
    expect(a).not.toBe(b);
    expect(await service.verify(a, 'same-password')).toBe(true);
    expect(await service.verify(b, 'same-password')).toBe(true);
  });

  it('verifies a correct password', async () => {
    const service = testService();
    const hash = await service.hash('my-secret-password');
    expect(await service.verify(hash, 'my-secret-password')).toBe(true);
  });

  it('rejects an incorrect password', async () => {
    const service = testService();
    const hash = await service.hash('my-secret-password');
    expect(await service.verify(hash, 'wrong-password')).toBe(false);
  });

  it('returns false for malformed hash strings instead of throwing', async () => {
    const service = testService();
    expect(await service.verify('not-a-hash', 'whatever')).toBe(false);
    expect(await service.verify('', 'whatever')).toBe(false);
  });

  it('defaults to production argon2id parameters (at least 19 MiB memory, timeCost 2)', () => {
    const service = new PasswordService();
    expect(service.parameters.algorithm).toBe('argon2id');
    expect(service.parameters.memoryCost).toBeGreaterThanOrEqual(19_456);
    expect(service.parameters.timeCost).toBeGreaterThanOrEqual(2);
    expect(service.parameters.parallelism).toBeGreaterThanOrEqual(1);
  });
});
