import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { v4 as uuid4 } from 'uuid';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import { SignUpDto } from './dtos/user-signup.dto';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dtos/user-login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { ResetPassword } from './schemas/reset-password.schema';
import { nanoid } from 'nanoid';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetPassword.name)
    private resetPasswordModel: Model<ResetPassword>,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async signUp(signupData: SignUpDto) {
    try {
      const { username, email, password } = signupData;

      const existingUser = await this.userModel.find({ email });
      if (existingUser.length > 0)
        throw new BadRequestException('Email already in use');

      const hashedPassword = bcrypt.hashSync(password, 10);
      const createdUser = await this.userModel.create({
        username,
        email,
        password: hashedPassword,
      });
      return createdUser;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }
  async login(loginData: LoginDto) {
    try {
      const { email, password } = loginData;

      const existingUser = await this.userModel.findOne({ email });
      if (!existingUser) throw new UnauthorizedException('Wrong credentials');

      const matchingPassword = bcrypt.compareSync(
        password,
        existingUser.password,
      );
      if (!matchingPassword)
        throw new UnauthorizedException('Wrong credentials');

      return this.createUserTokens(<string>existingUser._id);
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async createUserTokens(userId: any) {
    try {
      const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
      const refreshToken = uuid4();
      await this.storeRefreshToken(refreshToken, userId);
      return { accessToken, refreshToken };
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  }

  async storeRefreshToken(token: string, userId: string) {
    try {
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + 3);
      await this.refreshTokenModel.updateOne(
        { userId },
        { $set: { token, expiryDate } },
        { upsert: true },
      );
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  }

  async refreshTokens(refreshToken: string) {
    try {
      const token = await this.refreshTokenModel.findOneAndDelete({
        token: refreshToken,
        expiryDate: { $gte: new Date() },
      });
      if (!token) throw new UnauthorizedException('Invalid refresh token');
      return await this.createUserTokens(token.userId);
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  }

  async changePassword(
    userId: string,
    oldPassword: string,
    newPassword: string,
  ) {
    try {
      const user = await this.userModel.findById(userId);
      if (!user) throw new NotFoundException('user not found ...');

      const matchingPassword = bcrypt.compareSync(oldPassword, user.password);
      if (!matchingPassword)
        throw new UnauthorizedException('Wrong credentials');

      newPassword = bcrypt.hashSync(newPassword, 10);

      user.password = newPassword;
      await user.save();
      return {
        message: 'Update Password Done Successfully',
      };
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  }

  async forgotPassword(email: string) {
    try {
      const user = await this.userModel.findOne({ email });
      if (user) {
        const resetToken = nanoid(64);
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 1);
        await this.resetPasswordModel.create({
          token: resetToken,
          expiryDate,
          userId: user._id,
        });
        await this.mailService.sendResetPasswordMessage(user.email, resetToken);
      }
      return {
        message: 'Reset password link sent to your gmail, please check it..',
      };
    } catch (error) {
      throw new InternalServerErrorException(error.message)
    }
  }

  async resetPassword(resetToken: string, newPassword: string) {
    try {
      const existingToken = await this.resetPasswordModel.findOneAndDelete({
        token: resetToken,
        expiryDate: { $gte: new Date() },
      });
      if (!existingToken) throw new UnauthorizedException('Invalid link');

      const user = await this.userModel.findById(existingToken.userId);
      if (!user) throw new UnauthorizedException('Invalid link');

      user.password = bcrypt.hashSync(newPassword, 10);
      await user.save();
      return { message: 'Change password done successfully...' };
    } catch (error) {
      throw new InternalServerErrorException(error.message);
    }
  }
}
