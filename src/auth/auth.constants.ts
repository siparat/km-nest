export const AuthErrorMessages = {
	FAILED_AUTHORIZE: 'Не удалось авторизоваться',
	ALREADY_EXIST: 'Такой пользователь уже существует',
	NOT_FOUND: 'Пользователь не найден',
	WRONG_PASSWORD: 'Неверный пароль',
	UNVERIFIED: 'Аккаунт не подтверждён, проверьте почту',
	BLOCKED: 'Этот аккаунт заблокирован, проверьте почту'
} as const;

export const AuthCookieNames = {
	ACCESS_TOKEN: 'accessToken',
	REFRESH_TOKEN: 'refreshToken'
} as const;

export const ALLOWED_EMAIL_SERVICES = ['mail.ru', 'gmail.com', 'vk.com', 'yandex.ru'];
