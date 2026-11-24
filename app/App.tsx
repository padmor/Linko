import { StatusBar } from "expo-status-bar";
import { View } from "react-native";

/** Temporary app root. The approved Figma interface will be integrated separately. */
export default function App() {
  return (
    <View style={{ flex: 1 }}>
      <StatusBar style="auto" />
    </View>
  );
}
