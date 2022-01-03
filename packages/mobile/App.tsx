import React from "react";
import {
	SafeAreaView,
	TextInput,
	View,
	Button,
} from "react-native";

import { Buffer } from "buffer";
// @ts-ignore
import Hyperbeam from "hyperbeam";


const App = () => {
	const [beam, setBeam] = React.useState(null);
	const input = React.useRef<TextInput>(null);

	React.useEffect(() => {
		const beam = new Hyperbeam("tz7ymuvi2ub4tfy2goagpat3zcaj6nxs4rxatu6jhecjekvqz7ma", false);
		beam.on("data", (data: Buffer) => console.log(data.toString()));
		setBeam(beam);
	}, []);

	return (
		<SafeAreaView style={{ flex: 1, justifyContent: "space-around", alignItems: "center" }}>
			<View style={{ width: "80%", backgroundColor: "#AAAA00" }}>
				<TextInput
					ref={input}
					onSubmitEditing={(e) => {(beam as any)?.write(Buffer.from(e.nativeEvent.text)); input.current?.clear();}}
				></TextInput>
			</View>
			<Button title="Run udp tests" onPress={() => require("@void/utp-react-native/tests/udp")} ></Button>
			<Button title="Run sockets tests" onPress={() => require("@void/utp-react-native/tests/sockets")} ></Button>
			<Button title="Run timeouts tests" onPress={() => require("@void/utp-react-native/tests/timeouts")} ></Button>
			<Button title="Run net tests" onPress={() => require("@void/utp-react-native/tests/net")} ></Button>
		</SafeAreaView>
	);
};


export default App;
