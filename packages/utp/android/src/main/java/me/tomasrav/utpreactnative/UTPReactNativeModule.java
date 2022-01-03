package me.tomasrav.utpreactnative;

import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = UTPReactNativeModule.NAME)
public class UTPReactNativeModule extends ReactContextBaseJavaModule {
  public static final String NAME = "UTPReactNative";

  static {
    try {
      // Used to load the 'native-lib' library on application startup.
      System.loadLibrary("utp-react-native");
    } catch (Exception ignored) {
    }
  }

  public UTPReactNativeModule(ReactApplicationContext reactContext) {
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
      Log.e("UTPReactNative", "JSI Runtime is not available in debug mode");
    }

  }
}
