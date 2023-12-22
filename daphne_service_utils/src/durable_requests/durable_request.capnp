@0xd076f8051f8de41a;

enum Method {
    get @0;
    post @1;
    put @2;
    patch @3;
    delete @4;
    options @5;
    head @6;
    trace @7;
    connect @8;
}

struct DurableRequest @0xfbd55b93d47690b9 {
    binding @0 :Text;
    id :union {
        name @1 :Text;
        hex @2 :Text;
    }
    retry @3 :Bool;
}
