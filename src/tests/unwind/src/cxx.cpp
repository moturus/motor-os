namespace {
int static_constructor_result;

struct StaticConstructor {
    StaticConstructor() {
        try {
            throw 31;
        } catch (int value) {
            static_constructor_result = value;
        }
    }
};

StaticConstructor static_constructor;

struct Cleanup {
    unsigned long* counter;

    ~Cleanup() {
        ++*counter;
    }
};
}  // namespace

extern "C" int motor_cxx_catch_own() {
    try {
        throw 29;
    } catch (int value) {
        return value;
    }
    return 0;
}

extern "C" int motor_cxx_static_result() {
    return static_constructor_result;
}

extern "C" void motor_cxx_throw() {
    throw 37;
}

extern "C" int motor_cxx_catch_through_rust(void (*callback)()) {
    try {
        callback();
    } catch (int value) {
        return value;
    }
    return 0;
}

extern "C" void motor_cxx_call_rust(void (*callback)(), unsigned long* drops) {
    Cleanup cleanup{drops};
    callback();
}
