#include <iostream>

#include "extensions/transport_sockets/smtp_starttls/smtp_starttls_socket.h"

#include "common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace SmtpStartTls {

using absl::ascii_isdigit;

Network::IoResult SmtpStartTlsSocket::doRead(Buffer::Instance& buffer) {
  if (passthrough_) return passthrough_->doRead(buffer);

  Envoy::Buffer::OwnedImpl local_buffer;
  Network::IoResult result = raw_socket_->doRead(local_buffer);
  buffer.add(local_buffer);

  // if (local_buffer.length() + command_buffer_.size() > 1000) bad
  absl::StrAppend(&command_buffer_, local_buffer.toString());
  size_t lf = command_buffer_.find('\n');
  if (lf == std::string::npos) {
    return result;
  }
  // if (lf != command_buffer_.size() - 1) bad

  if (absl::StartsWithIgnoreCase(command_buffer_, "EHLO")) {
    ehlo_ = true;
  } else if (absl::EqualsIgnoreCase(command_buffer_, "STARTTLS\r\n")) {
    Envoy::Buffer::OwnedImpl outbuf;
    outbuf.add(absl::string_view("220 ready for tls\r\n"));
    raw_socket_->doWrite(outbuf, false);

    ssl_socket_->setTransportSocketCallbacks(*callbacks_);
    ssl_socket_->onConnected();
    passthrough_ = std::move(ssl_socket_);
    raw_socket_.reset();
  } else {
    // go to passthrough mode if we see any other unexpected commands, we may
    // need to allow e.g. NOOP/RSET but let's try being strict first
    passthrough_ = std::move(raw_socket_);
    ssl_socket_.reset();
  }

  command_buffer_.clear();

  return result;
}

// returns true if the input ends with the last line of a (possibly multiline)
// esmtp response
bool ScanEsmtpResponse(absl::string_view lines) {
  absl::string_view rest = lines;
  while (!rest.empty()) {
    size_t lf = rest.find('\n');
    if (lf == absl::string_view::npos) return false;  // precondition
    absl::string_view line = rest.substr(0, lf + 1);
    rest.remove_prefix(lf + 1);
    std::cout << line << std::endl;
    if (rest.empty() && line.size() >= 4 &&
        ascii_isdigit(line[0]) && ascii_isdigit(line[1]) && ascii_isdigit(line[2]) &&
        (line[3] == ' ')) {
      // you might want to accept 200\r\n though that is technically an invalid response
      return true;
    }
  }
  return false;
}

// given at least the last line of the esmtp ehlo response
// 250 pipelining
// (possibly more), add starttls
// 250-pipelining
// 250 starttls
void AddStarttlsToCapabilities(std::string* lines) {
  absl::string_view rest = *lines;
  while (!rest.empty()) {
    size_t lf = rest.find('\n');
    if (lf == absl::string_view::npos) return;  // precondition
    absl::string_view line = rest.substr(0, lf + 1);
    rest.remove_prefix(lf + 1);
    std::cout << line << std::endl;
    if (!rest.empty()) continue;
    if (line.size() < 5) return;  // precondition
    size_t off = line.data() - lines->data();
    (*lines)[off + 3] = '-';
    lines->append("250 STARTTLS\r\n");
  }
}

Network::IoResult SmtpStartTlsSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (passthrough_) return passthrough_->doWrite(buffer, end_stream);

  Envoy::Buffer::OwnedImpl local;
  local.move(buffer);
  absl::StrAppend(&response_buffer_, local.toString());
  if (!ScanEsmtpResponse(response_buffer_)) {
    return {Network::PostIoAction::KeepOpen, local.length(), false};
  }

  if (ehlo_) {
    AddStarttlsToCapabilities(&response_buffer_);
    ehlo_ = false;
  }

  local = Envoy::Buffer::OwnedImpl(response_buffer_);
  response_buffer_.clear();

  Network::IoResult result = raw_socket_->doWrite(local, end_stream);
  result.bytes_processed_ = local.length();
  return result;
}

// TODO: right now this just expects DownstreamTlsContext in
// TransportSocket.typed_config which it passes to both transport sockets. There
// probably needs to be a separate config proto for this that can hold the
// config protos for both RawBuffer/SslSocket.
Network::TransportSocketPtr ServerSmtpStartTlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsSharedPtr transport_socket_options) const {
    return std::make_unique<SmtpStartTlsSocket>(
        raw_socket_factory_->createTransportSocket(transport_socket_options),
        tls_socket_factory_->createTransportSocket(transport_socket_options),
        transport_socket_options);
}

ServerSmtpStartTlsSocketFactory::~ServerSmtpStartTlsSocketFactory() {}

}  // namespace SmtpStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
