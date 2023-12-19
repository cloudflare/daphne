fn main() {
    ::capnpc::CompilerCommand::new()
        .file("./src/durable_requests/durable_request.capnp")
        .run()
        .expect("compiling schema");
}
