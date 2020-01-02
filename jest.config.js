module.exports = {
	globalSetup: '<rootDir>/test/jest-setup.js',
	globalTeardown: '<rootDir>/test/jest-teardown.js',
	setupFilesAfterEnv: ['<rootDir>/test/jest-setup-test-framework.js'],
	testPathIgnorePatterns: ['/node_modules/'],
	modulePaths: ['<rootDir>/src'],
	testMatch: ['**/src/**/*.spec.js'],
	verbose: true,
	testEnvironment: 'jsdom',
	testURL: 'http://localhost/',
	collectCoverageFrom: ['src/**/*.js'],
	coverageReporters: ['json', 'lcov', 'text'],
	coverageDirectory: 'dist/coverage',
	coverageThreshold: {},
	transform: {
		'^.+\\.(js|jsx)$': 'babel-jest'
	}
};
