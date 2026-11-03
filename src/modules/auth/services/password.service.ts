import { Injectable } from '@nestjs/common';
import { Algorithm, hash, verify, type Options } from '@node-rs/argon2';

export interface Argon2Parameters {
  readonly algorithm: 'argon2id';
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
}

// OWASP-aligned floor; overridable in tests for speed.
const PRODUCTION_PARAMETERS: Argon2Parameters = {
  algorithm: 'argon2id',
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};

@Injectable()
export class PasswordService {
  readonly parameters: Argon2Parameters;

  constructor(parameters: Partial<Argon2Parameters> = {}) {
    this.parameters = { ...PRODUCTION_PARAMETERS, ...parameters };
  }

  async hash(plaintext: string): Promise<string> {
    const options: Options = {
      algorithm: Algorithm.Argon2id,
      memoryCost: this.parameters.memoryCost,
      timeCost: this.parameters.timeCost,
      parallelism: this.parameters.parallelism,
    };
    return hash(plaintext, options);
  }

  async verify(encodedHash: string, plaintext: string): Promise<boolean> {
    if (encodedHash.length === 0) {
      return false;
    }
    try {
      return await verify(encodedHash, plaintext);
    } catch {
      return false;
    }
  }
}
