fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos_with_config(
            config,
            &["../../proto/box_agent_v1.proto"],
            &["../../proto"],
        )
        .expect("compile box agent protobuf");
}
