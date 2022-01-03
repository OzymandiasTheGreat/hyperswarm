package me.tomasrav.sodiumreactnative;

import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = SodiumReactNativeModule.NAME)
public class SodiumReactNativeModule extends ReactContextBaseJavaModule {
  public static final String NAME = "SodiumReactNative";

  static {
    try {
      // Used to load the 'native-lib' library on application startup.
      System.loadLibrary("sodium-react-native");
    } catch (Exception ignored) {
    }
  }

  public SodiumReactNativeModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  private native void nativeInstall(long jsi);

  public void installLib(JavaScriptContextHolder reactContext) {

    if (reactContext.get() != 0) {
      this.nativeInstall(
        reactContext.get()
      );
    } else {
      Log.e("SodiumReactNative", "JSI Runtime is not available in debug mode");
    }

  }
}
