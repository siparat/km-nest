import { Injectable } from '@nestjs/common';
import { UserModel } from 'prisma/generated/common';
import { CommonDatabase } from 'src/database/common.database';

@Injectable()
export class UsersRepository {
	constructor(private database: CommonDatabase) {}

	async findUserWithInsensitiveMode(email: string, login: string): Promise<UserModel> {
		return this.database.userModel.findFirst({
			where: {
				OR: [{ email: { mode: 'insensitive', equals: email } }, { login: { mode: 'insensitive', equals: login } }]
			}
		});
	}
}
