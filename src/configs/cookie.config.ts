export const cookieConfig = {
	access: {
		httpOnly: false,
		maxAge: 5 * 24 * 60 * 60 * 1000,
		expires: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000)
	},
	refresh: {
		httpOnly: true,
		maxAge: 7 * 24 * 60 * 60 * 1000
	}
};
