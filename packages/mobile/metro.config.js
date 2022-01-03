/**
 * Metro configuration for React Native
 * https://github.com/facebook/react-native
 *
 * @format
 */

 const exclusionList = require("metro-config/src/defaults/exclusionList");
 const {
	 getMetroTools,
	 getMetroAndroidAssetsResolutionFix,
 } = require("react-native-monorepo-tools");

 const monorepoMetroTools = getMetroTools();
 const androidAssetsResolutionFix = getMetroAndroidAssetsResolutionFix();

 module.exports = {
	 transformer: {
		 publicPath: androidAssetsResolutionFix.publicPath,
		 getTransformOptions: async () => ({
			 transform: {
				 experimentalImportSupport: false,
				 inlineRequires: true,
			 },
		 }),
	 },
	 server: {
		 enhanceMiddleware: (middleware) => {
			 return androidAssetsResolutionFix.applyMiddleware(middleware);
		 },
	 },
	 watchFolders: monorepoMetroTools.watchFolders,
	 resolver: {
		 blockList: exclusionList(monorepoMetroTools.blockList),
		 extraNodeModules: {
			...monorepoMetroTools.extraNodeModules,
			crypto: require.resolve("react-native-crypto"),
			stream: require.resolve("readable-stream"),
			dgram: require.resolve("react-native-udp"),
			path: require.resolve("path-browserify"),
			net: require.resolve("react-native-tcp"),
			dns: require.resolve("fetch-dns"),
			os: require.resolve("react-native-os"),
			"stream-browserify": require.resolve("readable-stream"),
			"sodium-universal": require.resolve("@void/sodium-react-native"),
			"utp-native": require.resolve("@void/utp-react-native"),
			b4a: require.resolve("buffer"),
		 },
	 },
 };
