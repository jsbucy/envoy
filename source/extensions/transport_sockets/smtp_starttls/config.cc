#include "extensions/transport_sockets/smtp_starttls/config.h"
#include "common/config/utility.h"
#include "extensions/transport_sockets/smtp_starttls/smtp_starttls_socket.h"

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace SmtpStartTls {

Network::TransportSocketFactoryPtr
DownstreamSmtpStartTlsSocketFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {

  auto& raw_socket_config_factory =
  Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::DownstreamTransportSocketConfigFactory>("raw_buffer");

  Network::TransportSocketFactoryPtr raw_socket_factory =
      raw_socket_config_factory.createTransportSocketFactory(
          message /* *wrapped_socket_config_proto_for_factory */, context, server_names);

  auto& tls_socket_config_factory =
      Config::Utility::getAndCheckFactoryByName<
          Server::Configuration::DownstreamTransportSocketConfigFactory>("tls");

  Network::TransportSocketFactoryPtr tls_socket_factory =
      tls_socket_config_factory.createTransportSocketFactory(
          message /* *wrapped_socket_config_proto_for_factory */, context, server_names);


  return std::make_unique<ServerSmtpStartTlsSocketFactory>(
      server_names,
      std::move(raw_socket_factory),
      std::move(tls_socket_factory));
}

ProtobufTypes::MessagePtr DownstreamSmtpStartTlsSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext>();
}

REGISTER_FACTORY(DownstreamSmtpStartTlsSocketFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory){"smtp_starttls"};

}  // namespace SmtpStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
