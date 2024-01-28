import { DynamicModule, Module } from '@nestjs/common';
import { MoviesDatabase } from './movies.database';
import { CommonDatabase } from './common.database';

@Module({})
export class DatabaseModule {
	static forFeature(type: 'common' | 'movies'): DynamicModule {
		const database = type == 'common' ? CommonDatabase : MoviesDatabase;
		return {
			module: DatabaseModule,
			providers: [database],
			exports: [database]
		};
	}
}
