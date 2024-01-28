import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthErrorMessages } from '../auth.constants';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { AuthCookieNames } from '../auth.constants';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';
import { UserModel } from 'prisma/generated/common';
import { isJWT } from 'class-validator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
	constructor(
		private config: ConfigService,
		private authService: AuthService,
		private jwtService: JwtService
	) {
		super();
	}

	override handleRequest<TUser>(
		err: unknown,
		user: false | string,
		info: undefined | JsonWebTokenError | Error,
		context: ExecutionContext
	): TUser {
		if (info instanceof JsonWebTokenError || info instanceof Error) {
			throw new UnauthorizedException(AuthErrorMessages.FAILED_AUTHORIZE);
		}
		return super.handleRequest(err, user, info, context);
	}

	override async canActivate(context: ExecutionContext): Promise<boolean> {
		const req = context.switchToHttp().getRequest<Request>();
		const res = context.switchToHttp().getResponse<Response>();
		const accessPayload = await this.tokenIsValid(
			req.cookies[AuthCookieNames.ACCESS_TOKEN],
			AuthCookieNames.ACCESS_TOKEN
		);
		const refreshPayload = await this.tokenIsValid(
			req.cookies[AuthCookieNames.REFRESH_TOKEN],
			AuthCookieNames.REFRESH_TOKEN
		);

		if (!accessPayload && isJWT(req.cookies[AuthCookieNames.ACCESS_TOKEN]) && refreshPayload) {
			const newTokens = await this.authService.signTokens(refreshPayload.email);
			this.authService.setTokens(res, newTokens);
			req.cookies[AuthCookieNames.ACCESS_TOKEN] = newTokens.access;
		}

		if (!accessPayload && !refreshPayload) {
			this.authService.removeTokens(res);
			req.cookies[AuthCookieNames.ACCESS_TOKEN] = '';
		}

		return super.canActivate(context) as Promise<boolean>;
	}

	async tokenIsValid(
		token: string,
		type: (typeof AuthCookieNames)[keyof typeof AuthCookieNames]
	): Promise<false | Pick<UserModel, 'email'>> {
		try {
			const secretAccess = this.config.get('ACCESS_TOKEN_SECRET');
			const secretRefresh = this.config.get('REFRESH_TOKEN_SECRET');

			const payload = await this.jwtService.verifyAsync(token, {
				secret: type == 'accessToken' ? secretAccess : secretRefresh
			});

			const iat = Number(payload.iat);
			if (Number.isNaN(iat)) {
				return false;
			}

			const key = type == 'accessToken' ? 'ACCESS_TOKEN_EXPIRIES' : 'REFRESH_TOKEN_EXPIRIES';
			const duration = Number(this.config.get(key)) * 60;

			if (iat + duration < Date.now() / 1000) {
				return false;
			}

			return payload;
		} catch (error) {
			return false;
		}
	}
}
