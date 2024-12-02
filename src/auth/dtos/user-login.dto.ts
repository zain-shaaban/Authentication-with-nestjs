import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  @MaxLength(500)
  email: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(500)
  password: string;
}
