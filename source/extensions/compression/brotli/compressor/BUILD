load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "compressor_lib",
    srcs = ["brotli_compressor_impl.cc"],
    hdrs = ["brotli_compressor_impl.h"],
    external_deps = ["brotlienc"],
    deps = [
        "//include/envoy/compression/compressor:compressor_interface",
        "//source/common/buffer:buffer_lib",
        "//source/extensions/compression/brotli/common:brotli_base_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    category = "envoy.compression.compressor",
    security_posture = "robust_to_untrusted_downstream",
    deps = [
        ":compressor_lib",
        "//source/common/http:headers_lib",
        "//source/extensions/compression/common/compressor:compressor_factory_base_lib",
        "@envoy_api//envoy/extensions/compression/brotli/compressor/v3:pkg_cc_proto",
    ],
)
