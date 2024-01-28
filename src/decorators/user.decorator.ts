import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { Request } from 'express';

export const User = createParamDecorator((_: unknown, ctx: ExecutionContext) => {
	return ctx.switchToHttp().getRequest<Request>().user;
});
