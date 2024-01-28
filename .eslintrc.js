module.exports = {
	parser: '@typescript-eslint/parser',
	parserOptions: {
		project: 'tsconfig.json',
		tsconfigRootDir: __dirname,
		sourceType: 'module'
	},
	plugins: ['@typescript-eslint/eslint-plugin'],
	extends: ['plugin:@typescript-eslint/recommended', 'plugin:prettier/recommended'],
	root: true,
	env: {
		node: true,
		jest: true
	},
	ignorePatterns: ['.eslintrc.js'],
	rules: {
		'@typescript-eslint/interface-name-prefix': 'off',
		'@typescript-eslint/explicit-function-return-type': 'warn',
		'@typescript-eslint/explicit-module-boundary-types': 'off',
		'@typescript-eslint/no-explicit-any': 'warn',
		'@typescript-eslint/no-unused-vars': [
			'warn',
			{
				ignoreRestSiblings: true
			}
		],
		'prettier/prettier': [
			'warn',
			{
				useTabs: true,
				indentSize: 4,
				singleQuote: true,
				trailingComma: 'none',
				printWidth: 120,
				semi: true,
				bracketSpacing: true,
				bracketSameLine: true,
				arrowParens: 'always',
				parser: 'typescript',
				endOfLine: 'lf'
			}
		]
	}
};
