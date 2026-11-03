export abstract class MailerPort {
  abstract sendPasswordReset(to: string, token: string, expiresAt: Date): Promise<void>;
}
