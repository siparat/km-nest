import { IsBoolean, IsEmail, IsString, MaxLength, MinLength, IsAlphanumeric, Matches } from 'class-validator';
import { AllowedEmails } from './decorators/allowed-emails.decorator';
import { ALLOWED_EMAIL_SERVICES } from '../auth.constants';

export class UserRegisterDto {
	@AllowedEmails(ALLOWED_EMAIL_SERVICES)
	@IsEmail({}, { message: 'Неверно указан email' })
	email: string;

	@IsAlphanumeric('en-US', { message: 'Разрешено использовать только латинские буквы и цифры' })
	@MaxLength(14, { message: 'Максимальная длина логина – 14 символов' })
	@MinLength(4, { message: 'Минимальная длина логина – 4 символа' })
	@IsString({ message: 'Не указан логин' })
	login: string;

	@Matches(/^[0-9a-zA-Z!@#.$%^&*()_+|\-=]{1,}$/, {
		message: 'Пароль должен содержать только цифры, буквы и специальные символы'
	})
	@MinLength(8, { message: 'Минимальная длина пароля – 8 символов' })
	@MaxLength(21, { message: 'Максимальная длина пароля – 21 символ' })
	@IsString({ message: 'Не указан пароль' })
	password: string;

	@IsBoolean({ message: 'Поле notification должно содержать булевый тип' })
	notification: boolean;
}
