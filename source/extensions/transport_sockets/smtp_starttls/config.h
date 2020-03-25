#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "extensions/transport_sockets/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace SmtpStartTls {

class SmtpStartTlsSocketConfigFactory
    : public virtual Server::Configuration::TransportSocketConfigFactory {
 public:
  ~SmtpStartTlsSocketConfigFactory() override = default;
  std::string name() const override { return TransportSocketNames::get().SmtpStartTls; }
};

class DownstreamSmtpStartTlsSocketFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public SmtpStartTlsSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(DownstreamSmtpStartTlsSocketFactory);


}  // namespace SmtpStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
