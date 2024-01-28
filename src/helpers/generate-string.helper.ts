import { randomBytes } from 'crypto';

export const generateString = (length: number): string => {
	return randomBytes(length / 2)
		.toString('hex')
		.slice(0, length);
};
