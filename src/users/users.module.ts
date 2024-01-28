import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { UsersRepository } from './users.repository';
import { DatabaseModule } from 'src/database/database.module';

@Module({
	imports: [DatabaseModule.forFeature('common')],
	providers: [UsersService, UsersRepository],
	controllers: [UsersController],
	exports: [UsersRepository]
})
export class UsersModule {}
