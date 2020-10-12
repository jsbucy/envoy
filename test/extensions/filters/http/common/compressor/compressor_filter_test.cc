#include <memory>

#include "envoy/extensions/filters/http/compressor/v3/compressor.pb.h"

#include "common/protobuf/utility.h"

#include "extensions/filters/http/common/compressor/compressor.h"

#include "test/mocks/compression/compressor/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/protobuf/mocks.h"
#include "test/mocks/runtime/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace Compressors {

using testing::_;
using testing::Return;

class TestCompressorFilterConfig : public CompressorFilterConfig {
public:
  TestCompressorFilterConfig(
      const envoy::extensions::filters::http::compressor::v3::Compressor& compressor,
      const std::string& stats_prefix, Stats::Scope& scope, Runtime::Loader& runtime,
      const std::string& compressor_name)
      : CompressorFilterConfig(compressor, stats_prefix + compressor_name + ".", scope, runtime,
                               compressor_name) {}

  Envoy::Compression::Compressor::CompressorPtr makeCompressor() override {
    auto compressor = std::make_unique<Compression::Compressor::MockCompressor>();
    EXPECT_CALL(*compressor, compress(_, _)).Times(expected_compress_calls_);
    return compressor;
  }

  void setExpectedCompressCalls(uint32_t calls) { expected_compress_calls_ = calls; }

private:
  uint32_t expected_compress_calls_{1};
};

class CompressorFilterTest : public testing::Test {
public:
  CompressorFilterTest() {
    ON_CALL(runtime_.snapshot_, featureEnabled("test.filter_enabled", 100))
        .WillByDefault(Return(true));
  }

  void SetUp() override {
    setUpFilter(R"EOF(
{
  "compressor_library": {
     "name": "test",
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF");
  }

  // CompressorFilterTest Helpers
  void setUpFilter(std::string&& json) {
    envoy::extensions::filters::http::compressor::v3::Compressor compressor;
    TestUtility::loadFromJson(json, compressor);
    config_ =
        std::make_shared<TestCompressorFilterConfig>(compressor, "test.", stats_, runtime_, "test");
    filter_ = std::make_unique<CompressorFilter>(config_);
    filter_->setDecoderFilterCallbacks(decoder_callbacks_);
    filter_->setEncoderFilterCallbacks(encoder_callbacks_);
  }

  void verifyCompressedData() {
    EXPECT_EQ(expected_str_.length(), stats_.counter("test.test.total_uncompressed_bytes").value());
    EXPECT_EQ(data_.length(), stats_.counter("test.test.total_compressed_bytes").value());
  }

  void feedBuffer(uint64_t size) {
    TestUtility::feedBufferWithRandomCharacters(data_, size);
    expected_str_ += data_.toString();
  }

  void doRequest(Http::TestRequestHeaderMapImpl&& headers) {
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, false));
    Buffer::OwnedImpl data("hello");
    EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->decodeData(data, false));
    Http::TestRequestTrailerMapImpl trailers;
    EXPECT_EQ(Http::FilterTrailersStatus::Continue, filter_->decodeTrailers(trailers));
  }

  void doResponseCompression(Http::TestResponseHeaderMapImpl& headers, bool with_trailers) {
    doResponse(headers, true, with_trailers);
  }

  void doResponseNoCompression(Http::TestResponseHeaderMapImpl& headers) {
    doResponse(headers, false, true);
  }

  void doResponse(Http::TestResponseHeaderMapImpl& headers, bool with_compression,
                  bool with_trailers) {
    uint64_t buffer_content_size;
    if (!absl::SimpleAtoi(headers.get_("content-length"), &buffer_content_size)) {
      ASSERT_TRUE(
          StringUtil::CaseInsensitiveCompare()(headers.get_("transfer-encoding"), "chunked"));
      // In case of chunked stream just feed the buffer with 1000 bytes.
      buffer_content_size = 1000;
    }
    feedBuffer(buffer_content_size);
    Http::TestResponseHeaderMapImpl continue_headers;
    EXPECT_EQ(Http::FilterHeadersStatus::Continue,
              filter_->encode100ContinueHeaders(continue_headers));
    Http::MetadataMap metadata_map{{"metadata", "metadata"}};
    EXPECT_EQ(Http::FilterMetadataStatus::Continue, filter_->encodeMetadata(metadata_map));
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, false));

    if (with_compression) {
      EXPECT_EQ("", headers.get_("content-length"));
      EXPECT_EQ("test", headers.get_("content-encoding"));
      EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->encodeData(data_, !with_trailers));
      if (with_trailers) {
        EXPECT_CALL(encoder_callbacks_, addEncodedData(_, true))
            .WillOnce(Invoke([&](Buffer::Instance& data, bool) { data_.move(data); }));
        Http::TestResponseTrailerMapImpl trailers;
        EXPECT_EQ(Http::FilterTrailersStatus::Continue, filter_->encodeTrailers(trailers));
      }
      verifyCompressedData();
      EXPECT_EQ(1, stats_.counter("test.test.compressed").value());
    } else {
      EXPECT_EQ("", headers.get_("content-encoding"));
      EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->encodeData(data_, false));
      Http::TestResponseTrailerMapImpl trailers;
      EXPECT_EQ(Http::FilterTrailersStatus::Continue, filter_->encodeTrailers(trailers));
      EXPECT_EQ(1, stats_.counter("test.test.not_compressed").value());
    }
  }

  std::shared_ptr<TestCompressorFilterConfig> config_;
  std::unique_ptr<CompressorFilter> filter_;
  Buffer::OwnedImpl data_;
  std::string expected_str_;
  Stats::TestUtil::TestStore stats_;
  NiceMock<Runtime::MockLoader> runtime_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_callbacks_;
};

// Test if Runtime Feature is Disabled
TEST_F(CompressorFilterTest, DecodeHeadersWithRuntimeDisabled) {
  setUpFilter(R"EOF(
{
  "runtime_enabled": {
    "default_value": true,
    "runtime_key": "foo_key"
  },
  "compressor_library": {
     "name": "test",
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF");
  EXPECT_CALL(runtime_.snapshot_, getBoolean("foo_key", true))
      .Times(2)
      .WillRepeatedly(Return(false));
  doRequest({{":method", "get"}, {"accept-encoding", "deflate, test"}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  doResponseNoCompression(headers);
  EXPECT_FALSE(headers.has("vary"));
}

// Default config values.
TEST_F(CompressorFilterTest, DefaultConfigValues) {
  EXPECT_EQ(30, config_->minimumLength());
  EXPECT_EQ(false, config_->disableOnEtagHeader());
  EXPECT_EQ(false, config_->removeAcceptEncodingHeader());
  EXPECT_EQ(18, config_->contentTypeValues().size());
}

// Acceptance Testing with default configuration.
TEST_F(CompressorFilterTest, AcceptanceTestEncoding) {
  doRequest({{":method", "get"}, {"accept-encoding", "deflate, test"}});

  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  doResponseCompression(headers, false);
}

TEST_F(CompressorFilterTest, AcceptanceTestEncodingWithTrailers) {
  doRequest({{":method", "get"}, {"accept-encoding", "deflate, test"}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  config_->setExpectedCompressCalls(2);
  doResponseCompression(headers, true);
}

TEST_F(CompressorFilterTest, NoAcceptEncodingHeader) {
  doRequest({{":method", "get"}, {}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  doResponseNoCompression(headers);
  EXPECT_EQ(1, stats_.counter("test.test.no_accept_header").value());
  EXPECT_EQ("Accept-Encoding", headers.get_("vary"));
}

TEST_F(CompressorFilterTest, CacheIdentityDecision) {
  // check if identity stat is increased twice (the second time via the cached path).
  config_->setExpectedCompressCalls(0);
  doRequest({{":method", "get"}, {"accept-encoding", "identity"}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, false));
  EXPECT_EQ(1, stats_.counter("test.test.header_identity").value());
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, false));
  EXPECT_EQ(2, stats_.counter("test.test.header_identity").value());
}

TEST_F(CompressorFilterTest, CacheHeaderNotValidDecision) {
  // check if not_valid stat is increased twice (the second time via the cached path).
  config_->setExpectedCompressCalls(0);
  doRequest({{":method", "get"}, {"accept-encoding", "test;q=invalid"}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, false));
  EXPECT_EQ(1, stats_.counter("test.test.header_not_valid").value());
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, false));
  EXPECT_EQ(2, stats_.counter("test.test.header_not_valid").value());
}

// Content-Encoding: upstream response is already encoded.
TEST_F(CompressorFilterTest, ContentEncodingAlreadyEncoded) {
  doRequest({{":method", "get"}, {"accept-encoding", "test"}});
  Http::TestResponseHeaderMapImpl response_headers{
      {":method", "get"}, {"content-length", "256"}, {"content-encoding", "deflate, gzip"}};
  feedBuffer(256);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(response_headers, false));
  EXPECT_TRUE(response_headers.has("content-length"));
  EXPECT_FALSE(response_headers.has("transfer-encoding"));
  EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->encodeData(data_, false));
  EXPECT_EQ(1U, stats_.counter("test.test.not_compressed").value());
}

// No compression when upstream response is empty.
TEST_F(CompressorFilterTest, EmptyResponse) {
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {":status", "204"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->encodeHeaders(headers, true));
  EXPECT_EQ("", headers.get_("content-length"));
  EXPECT_EQ("", headers.get_("content-encoding"));
  EXPECT_EQ(Http::FilterDataStatus::Continue, filter_->encodeData(data_, true));
}

// Verify removeAcceptEncoding header.
TEST_F(CompressorFilterTest, RemoveAcceptEncodingHeader) {
  {
    Http::TestRequestHeaderMapImpl headers = {{"accept-encoding", "deflate, test, gzip, br"}};
    setUpFilter(R"EOF(
{
  "remove_accept_encoding_header": true,
  "compressor_library": {
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF");
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, true));
    EXPECT_FALSE(headers.has("accept-encoding"));
  }
  {
    Http::TestRequestHeaderMapImpl headers = {{"accept-encoding", "deflate, test, gzip, br"}};
    setUpFilter(R"EOF(
{
  "compressor_library": {
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF");
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers, true));
    EXPECT_TRUE(headers.has("accept-encoding"));
    EXPECT_EQ("deflate, test, gzip, br", headers.get_("accept-encoding"));
  }
}

class IsAcceptEncodingAllowedTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, bool, int, int, int, int>> {};

INSTANTIATE_TEST_SUITE_P(
    IsAcceptEncodingAllowedTestSuite, IsAcceptEncodingAllowedTest,
    testing::Values(std::make_tuple("deflate, test, br", true, 1, 0, 0, 0),
                    std::make_tuple("deflate, test;q=1.0, *;q=0.5", true, 1, 0, 0, 0),
                    std::make_tuple("\tdeflate\t, test\t ; q\t =\t 1.0,\t * ;q=0.5", true, 1, 0, 0,
                                    0),
                    std::make_tuple("deflate,test;q=1.0,*;q=0", true, 1, 0, 0, 0),
                    std::make_tuple("deflate, test;q=0.2, br;q=1", true, 1, 0, 0, 0),
                    std::make_tuple("*", true, 0, 1, 0, 0),
                    std::make_tuple("*;q=1", true, 0, 1, 0, 0),
                    std::make_tuple("xyz;q=1, br;q=0.2, *", true, 0, 1, 0, 0),
                    std::make_tuple("deflate, test;Q=.5, br", true, 1, 0, 0, 0),
                    std::make_tuple("test;q=0,*;q=1", false, 0, 0, 1, 0),
                    std::make_tuple("identity, *;q=0", false, 0, 0, 0, 1),
                    std::make_tuple("identity", false, 0, 0, 0, 1),
                    std::make_tuple("identity, *;q=0", false, 0, 0, 0, 1),
                    std::make_tuple("identity;q=1", false, 0, 0, 0, 1),
                    std::make_tuple("identity;q=0", false, 0, 0, 1, 0),
                    std::make_tuple("identity;Q=0", false, 0, 0, 1, 0),
                    std::make_tuple("identity;q=0.5, *;q=0", false, 0, 0, 0, 1),
                    std::make_tuple("identity;q=0, *;q=0", false, 0, 0, 1, 0),
                    std::make_tuple("xyz;q=1, br;q=0.2, *;q=0", false, 0, 0, 1, 0),
                    std::make_tuple("xyz;q=1, br;q=0.2", false, 0, 0, 1, 0),
                    std::make_tuple("", false, 0, 0, 1, 0),
                    std::make_tuple("test;q=invalid", false, 0, 0, 1, 0)));

TEST_P(IsAcceptEncodingAllowedTest, Validate) {
  const std::string& accept_encoding = std::get<0>(GetParam());
  const bool is_compression_expected = std::get<1>(GetParam());
  const int compressor_used = std::get<2>(GetParam());
  const int wildcard = std::get<3>(GetParam());
  const int not_valid = std::get<4>(GetParam());
  const int identity = std::get<5>(GetParam());

  doRequest({{":method", "get"}, {"accept-encoding", accept_encoding}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  doResponse(headers, is_compression_expected, false);
  EXPECT_EQ(compressor_used, stats_.counter("test.test.header_compressor_used").value());
  EXPECT_EQ(wildcard, stats_.counter("test.test.header_wildcard").value());
  EXPECT_EQ(not_valid, stats_.counter("test.test.header_not_valid").value());
  EXPECT_EQ(identity, stats_.counter("test.test.header_identity").value());
  // Even if compression is disallowed by a client we must let her know the resource is
  // compressible.
  EXPECT_EQ("Accept-Encoding", headers.get_("vary"));
}

class IsContentTypeAllowedTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, bool, bool>> {};

INSTANTIATE_TEST_SUITE_P(
    IsContentTypeAllowedTestSuite, IsContentTypeAllowedTest,
    testing::Values(
        std::make_tuple("text/html", true, false), std::make_tuple("text/xml", true, false),
        std::make_tuple("text/plain", true, false), std::make_tuple("text/css", true, false),
        std::make_tuple("application/javascript", true, false),
        std::make_tuple("application/x-javascript", true, false),
        std::make_tuple("text/javascript", true, false),
        std::make_tuple("text/x-javascript", true, false),
        std::make_tuple("text/ecmascript", true, false), std::make_tuple("text/js", true, false),
        std::make_tuple("text/jscript", true, false), std::make_tuple("text/x-js", true, false),
        std::make_tuple("application/ecmascript", true, false),
        std::make_tuple("application/x-json", true, false),
        std::make_tuple("application/xml", true, false),
        std::make_tuple("application/json", true, false),
        std::make_tuple("image/svg+xml", true, false),
        std::make_tuple("application/xhtml+xml", true, false),
        std::make_tuple("application/json;charset=utf-8", true, false),
        std::make_tuple("Application/XHTML+XML", true, false),
        std::make_tuple("\ttext/html\t", true, false), std::make_tuple("image/jpeg", false, false),
        std::make_tuple("xyz/svg+xml", true, true), std::make_tuple("xyz/false", false, true),
        std::make_tuple("image/jpeg", false, true),
        std::make_tuple("test/insensitive", true, true)));

TEST_P(IsContentTypeAllowedTest, Validate) {
  const std::string& content_type = std::get<0>(GetParam());
  const bool should_compress = std::get<1>(GetParam());
  const bool is_custom_config = std::get<2>(GetParam());

  if (is_custom_config) {
    setUpFilter(R"EOF(
      {
        "content_type": [
          "text/html",
          "xyz/svg+xml",
          "Test/INSENSITIVE"
        ],
    "compressor_library": {
       "name": "test",
       "typed_config": {
         "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
       }
    }
      }
    )EOF");
  }

  doRequest({{":method", "get"}, {"accept-encoding", "test, deflate"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {"content-type", content_type}};
  doResponse(headers, should_compress, false);
  EXPECT_EQ(should_compress ? 0 : 1, stats_.counter("test.test.header_not_valid").value());
  EXPECT_EQ(should_compress, headers.has("vary"));
}

class CompressWithEtagTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, std::string, bool>> {};

INSTANTIATE_TEST_SUITE_P(
    CompressWithEtagSuite, CompressWithEtagTest,
    testing::Values(std::make_tuple("etag", R"EOF(W/"686897696a7c876b7e")EOF", true),
                    std::make_tuple("etag", R"EOF(w/"686897696a7c876b7e")EOF", true),
                    std::make_tuple("etag", "686897696a7c876b7e", false),
                    std::make_tuple("x-garbage", "garbagevalue", false)));

TEST_P(CompressWithEtagTest, CompressionIsEnabledOnEtag) {
  const std::string& header_name = std::get<0>(GetParam());
  const std::string& header_value = std::get<1>(GetParam());
  const bool is_weak_etag = std::get<2>(GetParam());

  doRequest({{":method", "get"}, {"accept-encoding", "test, deflate"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {header_name, header_value}};
  doResponseCompression(headers, false);
  EXPECT_EQ(0, stats_.counter("test.test.not_compressed_etag").value());
  EXPECT_EQ("test", headers.get_("content-encoding"));
  if (is_weak_etag) {
    EXPECT_EQ(header_value, headers.get_("etag"));
  } else {
    EXPECT_FALSE(headers.has("etag"));
  }
}

TEST_P(CompressWithEtagTest, CompressionIsDisabledOnEtag) {
  const std::string& header_name = std::get<0>(GetParam());
  const std::string& header_value = std::get<1>(GetParam());

  setUpFilter(R"EOF(
{
  "disable_on_etag_header": true,
  "compressor_library": {
     "name": "test",
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF");

  doRequest({{":method", "get"}, {"accept-encoding", "test, deflate"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {header_name, header_value}};
  if (StringUtil::CaseInsensitiveCompare()("etag", header_name)) {
    doResponseNoCompression(headers);
    EXPECT_EQ(1, stats_.counter("test.test.not_compressed_etag").value());
    EXPECT_FALSE(headers.has("vary"));
    EXPECT_TRUE(headers.has("etag"));
  } else {
    doResponseCompression(headers, false);
    EXPECT_EQ(0, stats_.counter("test.test.not_compressed_etag").value());
    EXPECT_EQ("test", headers.get_("content-encoding"));
    EXPECT_TRUE(headers.has("vary"));
    EXPECT_FALSE(headers.has("etag"));
  }
}

class HasCacheControlNoTransformTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, bool>> {};

INSTANTIATE_TEST_SUITE_P(HasCacheControlNoTransformTestSuite, HasCacheControlNoTransformTest,
                         testing::Values(std::make_tuple("no-cache", true),
                                         std::make_tuple("no-transform", false),
                                         std::make_tuple("No-Transform", false)));

TEST_P(HasCacheControlNoTransformTest, Validate) {
  const std::string& cache_control = std::get<0>(GetParam());
  const bool is_compression_expected = std::get<1>(GetParam());

  doRequest({{":method", "get"}, {"accept-encoding", "test, deflate"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {"cache-control", cache_control}};
  doResponse(headers, is_compression_expected, false);
  EXPECT_EQ(is_compression_expected, headers.has("vary"));
}

class IsMinimumContentLengthTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, std::string, std::string, bool>> {
};

INSTANTIATE_TEST_SUITE_P(
    IsMinimumContentLengthTestSuite, IsMinimumContentLengthTest,
    testing::Values(std::make_tuple("content-length", "31", "", true),
                    std::make_tuple("content-length", "29", "", false),
                    std::make_tuple("transfer-encoding", "chunked", "", true),
                    std::make_tuple("transfer-encoding", "Chunked", "", true),
                    std::make_tuple("transfer-encoding", "chunked", "\"content_length\": 500,",
                                    true),
                    std::make_tuple("content-length", "501", "\"content_length\": 500,", true),
                    std::make_tuple("content-length", "499", "\"content_length\": 500,", false)));

TEST_P(IsMinimumContentLengthTest, Validate) {
  const std::string& header_name = std::get<0>(GetParam());
  const std::string& header_value = std::get<1>(GetParam());
  const std::string& content_length_config = std::get<2>(GetParam());
  const bool is_compression_expected = std::get<3>(GetParam());

  setUpFilter(fmt::format(R"EOF(
{{
  {}
  "compressor_library": {{
     "name": "test",
     "typed_config": {{
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }}
  }}
}}
)EOF",
                          content_length_config));

  doRequest({{":method", "get"}, {"accept-encoding", "test, deflate"}});
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {header_name, header_value}};
  doResponse(headers, is_compression_expected, false);
  EXPECT_EQ(is_compression_expected, headers.has("vary"));
}

class IsTransferEncodingAllowedTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, std::string, bool>> {};

INSTANTIATE_TEST_SUITE_P(
    IsTransferEncodingAllowedSuite, IsTransferEncodingAllowedTest,
    testing::Values(std::make_tuple("transfer-encoding", "chunked", true),
                    std::make_tuple("transfer-encoding", "Chunked", true),
                    std::make_tuple("transfer-encoding", "deflate", false),
                    std::make_tuple("transfer-encoding", "Deflate", false),
                    std::make_tuple("transfer-encoding", "test", false),
                    std::make_tuple("transfer-encoding", "chunked, test", false),
                    std::make_tuple("transfer-encoding", "test, chunked", false),
                    std::make_tuple("transfer-encoding", "test\t, chunked\t", false),
                    std::make_tuple("x-garbage", "no_value", true)));

TEST_P(IsTransferEncodingAllowedTest, Validate) {
  const std::string& header_name = std::get<0>(GetParam());
  const std::string& header_value = std::get<1>(GetParam());
  const bool is_compression_expected = std::get<2>(GetParam());

  doRequest({{":method", "get"}, {"accept-encoding", "test"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {header_name, header_value}};
  doResponse(headers, is_compression_expected, false);
  EXPECT_EQ("Accept-Encoding", headers.get_("vary"));
}

class InsertVaryHeaderTest
    : public CompressorFilterTest,
      public testing::WithParamInterface<std::tuple<std::string, std::string, std::string>> {};

INSTANTIATE_TEST_SUITE_P(
    InsertVaryHeaderTestSuite, InsertVaryHeaderTest,
    testing::Values(std::make_tuple("x-garbage", "Cookie", "Accept-Encoding"),
                    std::make_tuple("vary", "Cookie", "Cookie, Accept-Encoding"),
                    std::make_tuple("vary", "accept-encoding", "accept-encoding, Accept-Encoding"),
                    std::make_tuple("vary", "Accept-Encoding, Cookie", "Accept-Encoding, Cookie"),
                    std::make_tuple("vary", "User-Agent, Cookie",
                                    "User-Agent, Cookie, Accept-Encoding"),
                    std::make_tuple("vary", "Accept-Encoding", "Accept-Encoding")));

TEST_P(InsertVaryHeaderTest, Validate) {
  const std::string& header_name = std::get<0>(GetParam());
  const std::string& header_value = std::get<1>(GetParam());
  const std::string& expected = std::get<2>(GetParam());

  doRequest({{":method", "get"}, {"accept-encoding", "test"}});
  Http::TestResponseHeaderMapImpl headers{
      {":method", "get"}, {"content-length", "256"}, {header_name, header_value}};
  doResponseCompression(headers, false);
  EXPECT_EQ(expected, headers.get_("vary"));
}

class MultipleFiltersTest : public testing::Test {
protected:
  void SetUp() override {
    envoy::extensions::filters::http::compressor::v3::Compressor compressor;
    TestUtility::loadFromJson(R"EOF(
{
  "compressor_library": {
     "name": "test1",
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF",
                              compressor);
    auto config1 = std::make_shared<TestCompressorFilterConfig>(compressor, "test1.", stats1_,
                                                                runtime_, "test1");
    config1->setExpectedCompressCalls(0);
    filter1_ = std::make_unique<CompressorFilter>(config1);

    TestUtility::loadFromJson(R"EOF(
{
  "compressor_library": {
     "name": "test2",
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF",
                              compressor);
    auto config2 = std::make_shared<TestCompressorFilterConfig>(compressor, "test2.", stats2_,
                                                                runtime_, "test2");
    config2->setExpectedCompressCalls(0);
    filter2_ = std::make_unique<CompressorFilter>(config2);
  }

  NiceMock<Runtime::MockLoader> runtime_;
  Stats::TestUtil::TestStore stats1_;
  Stats::TestUtil::TestStore stats2_;
  std::unique_ptr<CompressorFilter> filter1_;
  std::unique_ptr<CompressorFilter> filter2_;
};

TEST_F(MultipleFiltersTest, IndependentFilters) {
  // The compressor "test1" from an independent filter chain should not overshadow "test2".
  // The independence is simulated with different instances of DecoderFilterCallbacks set for
  // "test1" and "test2".
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks1;
  filter1_->setDecoderFilterCallbacks(decoder_callbacks1);
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks2;
  filter2_->setDecoderFilterCallbacks(decoder_callbacks2);

  Http::TestRequestHeaderMapImpl req_headers{{":method", "get"},
                                             {"accept-encoding", "test1;Q=.5,test2;q=0.75"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->decodeHeaders(req_headers, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->decodeHeaders(req_headers, false));
  Http::TestResponseHeaderMapImpl headers1{{":method", "get"}, {"content-length", "256"}};
  Http::TestResponseHeaderMapImpl headers2{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->encodeHeaders(headers1, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->encodeHeaders(headers2, false));
  EXPECT_EQ(0, stats1_.counter("test1.test1.header_compressor_overshadowed").value());
  EXPECT_EQ(0, stats2_.counter("test2.test2.header_compressor_overshadowed").value());
  EXPECT_EQ(1, stats1_.counter("test1.test1.compressed").value());
  EXPECT_EQ(1, stats1_.counter("test1.test1.header_compressor_used").value());
  EXPECT_EQ(1, stats2_.counter("test2.test2.compressed").value());
  EXPECT_EQ(1, stats2_.counter("test2.test2.header_compressor_used").value());
}

TEST_F(MultipleFiltersTest, CacheEncodingDecision) {
  // Test that encoding decision is cached when used by multiple filters.
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks;
  filter1_->setDecoderFilterCallbacks(decoder_callbacks);
  filter2_->setDecoderFilterCallbacks(decoder_callbacks);

  Http::TestRequestHeaderMapImpl req_headers{{":method", "get"},
                                             {"accept-encoding", "test1;Q=.5,test2;q=0.75"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->decodeHeaders(req_headers, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->decodeHeaders(req_headers, false));
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->encodeHeaders(headers, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->encodeHeaders(headers, false));
  EXPECT_EQ(1, stats1_.counter("test1.test1.header_compressor_overshadowed").value());
  EXPECT_EQ(1, stats2_.counter("test2.test2.header_compressor_used").value());
  // Reset headers as content-length got removed by filter2.
  headers = {{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->encodeHeaders(headers, false));
  EXPECT_EQ(2, stats1_.counter("test1.test1.header_compressor_overshadowed").value());
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->encodeHeaders(headers, false));
  EXPECT_EQ(2, stats2_.counter("test2.test2.header_compressor_used").value());
}

TEST_F(MultipleFiltersTest, UseFirstRegisteredFilterWhenWildcard) {
  // Test that first registered filter is used when handling wildcard.
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks;
  filter1_->setDecoderFilterCallbacks(decoder_callbacks);
  filter2_->setDecoderFilterCallbacks(decoder_callbacks);

  Http::TestRequestHeaderMapImpl req_headers{{":method", "get"}, {"accept-encoding", "*"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->decodeHeaders(req_headers, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->decodeHeaders(req_headers, false));
  Http::TestResponseHeaderMapImpl headers1{{":method", "get"}, {"content-length", "256"}};
  Http::TestResponseHeaderMapImpl headers2{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter1_->encodeHeaders(headers1, false));
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter2_->encodeHeaders(headers2, false));
  EXPECT_EQ(1, stats1_.counter("test1.test1.compressed").value());
  EXPECT_EQ(0, stats2_.counter("test2.test2.compressed").value());
  EXPECT_EQ(1, stats1_.counter("test1.test1.header_wildcard").value());
  EXPECT_EQ(1, stats2_.counter("test2.test2.header_wildcard").value());
}

TEST(LegacyTest, GzipStats) {
  // check if the legacy "header_gzip" counter is incremented for gzip compression filter
  Stats::TestUtil::TestStore stats;
  NiceMock<Runtime::MockLoader> runtime;
  envoy::extensions::filters::http::compressor::v3::Compressor compressor;
  TestUtility::loadFromJson(R"EOF(
{
  "compressor_library": {
     "typed_config": {
       "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
     }
  }
}
)EOF",
                            compressor);
  auto config =
      std::make_shared<TestCompressorFilterConfig>(compressor, "test.", stats, runtime, "gzip");
  config->setExpectedCompressCalls(0);
  auto gzip_filter = std::make_unique<CompressorFilter>(config);
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_callbacks;
  gzip_filter->setDecoderFilterCallbacks(decoder_callbacks);
  Http::TestRequestHeaderMapImpl req_headers{{":method", "get"},
                                             {"accept-encoding", "gzip;q=0.75"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, gzip_filter->decodeHeaders(req_headers, false));
  Http::TestResponseHeaderMapImpl headers{{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, gzip_filter->encodeHeaders(headers, false));
  EXPECT_EQ(1, stats.counter("test.gzip.header_gzip").value());
  EXPECT_EQ(1, stats.counter("test.gzip.compressed").value());
  // Reset headers as content-length got removed by gzip_filter.
  headers = {{":method", "get"}, {"content-length", "256"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, gzip_filter->encodeHeaders(headers, false));
  EXPECT_EQ(2, stats.counter("test.gzip.header_gzip").value());
  EXPECT_EQ(2, stats.counter("test.gzip.compressed").value());
}

} // namespace Compressors
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
