import { ValidationOptions, registerDecorator } from 'class-validator';

export const AllowedEmails = (domains: string[], options?: ValidationOptions) => {
	return function (object: object, propertyName: string): void {
		registerDecorator({
			name: 'AllowedEmails',
			target: object.constructor,
			propertyName: propertyName,
			options,
			validator: {
				validate: (email: string) => {
					const startPosition = email.indexOf('@') + 1;
					return domains.includes(email.substring(startPosition));
				},
				defaultMessage: () => `Используйте разрешенные почтовые сервисы ${domains.join(', ')}`
			}
		});
	};
};
