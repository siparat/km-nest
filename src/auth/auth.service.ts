import { BadRequestException, ForbiddenException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { UserRegisterDto } from './dto/user-register.dto';
import { UserModel } from 'prisma/generated/common';
import { CommonDatabase } from 'src/database/common.database';
import { AuthCookieNames, AuthErrorMessages } from './auth.constants';
import { ConfigService } from '@nestjs/config';
import { compare, hash } from 'bcrypt';
import { generateString } from 'src/helpers/generate-string.helper';
import { UserLoginDto } from './dto/user-login.dto';
import { Tokens } from './auth.interfaces';
import { JwtService } from '@nestjs/jwt';
import { UsersRepository } from 'src/users/users.repository';
import { Response } from 'express';
import { cookieConfig } from 'src/configs/cookie.config';

@Injectable()
export class AuthService {
	constructor(
		private database: CommonDatabase,
		private config: ConfigService,
		private jwtService: JwtService,
		private usersRepository: UsersRepository
	) {}

	async register({ email, password, login, notification }: UserRegisterDto): Promise<UserModel> {
		const existingUser = await this.usersRepository.findUserWithInsensitiveMode(email, login);
		if (existingUser) {
			throw new BadRequestException(AuthErrorMessages.ALREADY_EXIST);
		}

		const salt = Number(this.config.get('SALT'));
		const passwordHash = await hash(password, salt);

		const user = await this.createUser({ email, login, password: passwordHash, notification });
		Logger.log(`[UsersService] Пользователь с email: ${email} успешно зарегистрирован`);

		// if (createdUser.confirmToken) {
		// 	const result = await this.emailService.sendConfirmEmail(
		// 		createdUser.email,
		// 		createdUser.login,
		// 		createdUser.confirmToken
		// 	);
		// 	if (result instanceof HTTPError) return result;
		// }

		// await this.awardsService.updateOpenAwardsInUser(createdUser.id, AwardCategory.RANKS);
		// await this.awardsService.updateOpenAwardsInUser(createdUser.id, AwardCategory.REGISTER);
		// await this.awardsService.updateOpenAwardsInUser(createdUser.id, AwardCategory.POINTS);

		return user;
	}

	async auth({ email, password }: UserLoginDto): Promise<Tokens> {
		const user = await this.database.userModel.findUnique({ where: { email } });
		if (!user) {
			throw new UnauthorizedException(AuthErrorMessages.NOT_FOUND);
		}
		if (!(await compare(password, user.password))) {
			throw new UnauthorizedException(AuthErrorMessages.WRONG_PASSWORD);
		}
		// if (!user.verified) {
		// 	throw new UnauthorizedException(AuthErrorMessages.UNVERIFIED);
		// }
		if (user.blocked) {
			throw new ForbiddenException(AuthErrorMessages.BLOCKED);
		}

		Logger.log(`[UsersService] Пользователь с email: ${email} успешно авторизован`);

		return this.signTokens(email);
	}

	async signTokens(email: string): Promise<Tokens> {
		const secretAccess = this.config.get('ACCESS_TOKEN_SECRET');
		const secretRefresh = this.config.get('REFRESH_TOKEN_SECRET');
		const iat = Math.floor(Date.now() / 1000);
		return {
			access: await this.jwtService.signAsync({ email, iat }, { secret: secretAccess }),
			refresh: await this.jwtService.signAsync({ email, iat }, { secret: secretRefresh })
		};
	}

	setTokens(res: Response, tokens: Tokens): void {
		res.cookie(AuthCookieNames.ACCESS_TOKEN, tokens.access, cookieConfig.access);
		res.cookie(AuthCookieNames.REFRESH_TOKEN, tokens.refresh, cookieConfig.refresh);
	}

	removeTokens(res: Response): void {
		res.clearCookie(AuthCookieNames.ACCESS_TOKEN);
		res.clearCookie(AuthCookieNames.REFRESH_TOKEN);
	}

	private async createUser({ email, login, password, notification }: UserRegisterDto): Promise<UserModel> {
		const notificationToken = `${generateString(40)}_${login}`;
		const confirmToken = `${generateString(40)}_${login}`;
		return this.database.userModel.create({
			data: { email, login, password, notification, notificationToken, confirmToken }
		});
	}
}
