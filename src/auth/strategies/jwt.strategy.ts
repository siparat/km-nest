import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, StrategyOptionsWithoutRequest } from 'passport-jwt';
import { UserModel } from 'prisma/generated/common';
import { CommonDatabase } from 'src/database/common.database';
import { AuthCookieNames, AuthErrorMessages } from '../auth.constants';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private config: ConfigService,
		private database: CommonDatabase,
		private authService: AuthService
	) {
		const options: StrategyOptionsWithoutRequest = {
			secretOrKey: config.get('ACCESS_TOKEN_SECRET'),
			jwtFromRequest: (req: Request) => req.cookies[AuthCookieNames.ACCESS_TOKEN] ?? null,
			ignoreExpiration: true
		};
		super(options);
	}

	async validate({ email }: Pick<UserModel, 'email'>): Promise<UserModel> {
		const user = await this.database.userModel.findUnique({ where: { email } });
		if (!user) {
			throw new UnauthorizedException(AuthErrorMessages.FAILED_AUTHORIZE);
		}
		return user;
	}
}
