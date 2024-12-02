import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, userSchema } from './schemas/user.schema';
import {
  RefreshToken,
  refreshTokenSchema,
} from './schemas/refresh-token.schema';
import {
  ResetPassword,
  resetPasswordSchema,
} from './schemas/reset-password.schema';
import { MailService } from 'src/mail/mail.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: userSchema },
      { name: RefreshToken.name, schema: refreshTokenSchema },
      { name: ResetPassword.name, schema: resetPasswordSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService,MailService],
})
export class AuthModule {}
