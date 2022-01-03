#ifndef SODIUM_REACT_NATIVE_H
#define SODIUM_REACT_NATIVE_H


namespace facebook {
namespace jsi {
class Runtime;
}
}


namespace sodium_react_native {

void install(facebook::jsi::Runtime &jsiRuntime);

}


#endif /* SODIUM_REACT_NATIVE_H */
