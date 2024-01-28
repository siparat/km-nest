import {
	Body,
	Controller,
	HttpCode,
	HttpStatus,
	Post,
	Get,
	Res,
	UsePipes,
	ValidationPipe,
	UseGuards
} from '@nestjs/common';
import { UserRegisterDto } from './dto/user-register.dto';
import { Tokens } from './auth.interfaces';
import { AuthService } from './auth.service';
import { UserModel } from 'prisma/generated/common';
import { UserLoginDto } from './dto/user-login.dto';
import { Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { User } from 'src/decorators/user.decorator';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@UsePipes(ValidationPipe)
	@Post('register')
	async register(@Body() dto: UserRegisterDto): Promise<Omit<UserModel, 'confirmToken'>> {
		const { confirmToken, ...user } = await this.authService.register(dto);
		return user;
	}

	@UsePipes(ValidationPipe)
	@HttpCode(HttpStatus.OK)
	@Post('login')
	async login(@Body() dto: UserLoginDto, @Res({ passthrough: true }) res: Response): Promise<Tokens> {
		const tokens = await this.authService.auth(dto);
		this.authService.setTokens(res, tokens);
		return tokens;
	}

	@UseGuards(JwtAuthGuard)
	@Get('info')
	info(@User() user: UserModel): UserModel {
		return user;
	}
}
