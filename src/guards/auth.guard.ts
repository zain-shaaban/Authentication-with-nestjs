import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    try {
      const request = context.switchToHttp().getRequest();
      const token = this.extractBearerToken(request);
      if (!token) throw new UnauthorizedException('Invalid token');
      const payload = this.jwtService.verify(token);
      request.userId = payload.userId;
      return true;
    } catch (error) {
      Logger.error(error);
      throw new UnauthorizedException('Invalid token')
    }
  }
  extractBearerToken(request: Request) {
    return request.headers.authorization?.split(' ')[1];
  }
}