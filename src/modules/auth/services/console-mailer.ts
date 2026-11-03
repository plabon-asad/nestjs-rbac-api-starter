import { Injectable, Logger } from '@nestjs/common';
import { MailerPort } from '../interfaces/mailer.port.js';

/**
 * Development-only mailer: prints the reset link material to the log.
 * Replace the MailerPort binding in production (SES, SMTP, Postmark, ...).
 */
@Injectable()
export class ConsoleMailer implements MailerPort {
  private readonly logger = new Logger(ConsoleMailer.name);

  sendPasswordReset(to: string, token: string, expiresAt: Date): Promise<void> {
    this.logger.log(`Password reset for ${to}: token=${token} expires=${expiresAt.toISOString()}`);
    return Promise.resolve();
  }
}
