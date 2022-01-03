module.exports = {
	presets: ["module:metro-react-native-babel-preset"],
	plugins: ["@babel/plugin-proposal-async-generator-functions", [
		"module-resolver",
		{
			alias: {
				"sodium-universal": "@void/sodium-react-native",
				"utp-native": "@void/utp-react-native",
			},
		},
	]],
};
