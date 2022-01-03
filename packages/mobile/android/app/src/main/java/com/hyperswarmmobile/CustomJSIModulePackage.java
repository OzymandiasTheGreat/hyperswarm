package com.hyperswarmmobile;

import com.facebook.react.bridge.JSIModulePackage;
import com.facebook.react.bridge.JSIModuleSpec;
import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import java.util.Collections;
import java.util.List;

import me.tomasrav.sodiumreactnative.SodiumReactNativeModulePackage;
import me.tomasrav.utpreactnative.UTPReactNativeModule;


public class CustomJSIModulePackage extends SodiumReactNativeModulePackage {
    @Override
    public List<JSIModuleSpec> getJSIModules(ReactApplicationContext reactApplicationContext, JavaScriptContextHolder jsContext) {
        reactApplicationContext.getNativeModule(UTPReactNativeModule.class).installLib(jsContext);
        return super.getJSIModules(reactApplicationContext, jsContext);
    }
}
