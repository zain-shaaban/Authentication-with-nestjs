import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  @IsNotEmpty()
  oldPassword: string;

  @MinLength(6)
  @IsString()
  @IsNotEmpty()
  newPassword: string;
}
