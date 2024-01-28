import { IsEmail, MinLength, IsString } from 'class-validator';
import { ALLOWED_EMAIL_SERVICES } from '../auth.constants';
import { AllowedEmails } from './decorators/allowed-emails.decorator';

export class UserLoginDto {
	@AllowedEmails(ALLOWED_EMAIL_SERVICES)
	@IsEmail({}, { message: 'Неверно указан email' })
	email: string;

	@MinLength(8, { message: 'Минимальная длина пароля – 8 символов' })
	@IsString({ message: 'Не указан пароль' })
	password: string;
}
