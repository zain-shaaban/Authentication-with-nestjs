import { BadRequestException, HttpException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}
  async sendResetPasswordMessage(to: string, token: string) {
    try {
      const resetLink = `http://your_front/resetpassword?token=${token}`;
      await this.mailerService.sendMail({
        to,
        subject: 'Auth-BackEnd Service',
        html: `<p>You requested a password reset, Click the link below to reset your password:</p><p><a href="${resetLink}">Reset Password</a></p>`,
      });
    } catch (error) {
      throw new InternalServerErrorException(error.message)
    }
  }
}
