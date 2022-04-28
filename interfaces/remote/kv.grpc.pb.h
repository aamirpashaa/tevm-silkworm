// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: remote/kv.proto
#ifndef GRPC_remote_2fkv_2eproto__INCLUDED
#define GRPC_remote_2fkv_2eproto__INCLUDED

#include "remote/kv.pb.h"

#include <functional>
#include <grpcpp/impl/codegen/async_generic_service.h>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/client_context.h>
#include <grpcpp/impl/codegen/completion_queue.h>
#include <grpcpp/impl/codegen/message_allocator.h>
#include <grpcpp/impl/codegen/method_handler.h>
#include <grpcpp/impl/codegen/proto_utils.h>
#include <grpcpp/impl/codegen/rpc_method.h>
#include <grpcpp/impl/codegen/server_callback.h>
#include <grpcpp/impl/codegen/server_callback_handlers.h>
#include <grpcpp/impl/codegen/server_context.h>
#include <grpcpp/impl/codegen/service_type.h>
#include <grpcpp/impl/codegen/status.h>
#include <grpcpp/impl/codegen/stub_options.h>
#include <grpcpp/impl/codegen/sync_stream.h>

namespace remote {

// Provides methods to access key-value data
class KV final {
 public:
  static constexpr char const* service_full_name() {
    return "remote.KV";
  }
  class StubInterface {
   public:
    virtual ~StubInterface() {}
    // Version returns the service version number
    virtual ::grpc::Status Version(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::types::VersionReply* response) = 0;
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>> AsyncVersion(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>>(AsyncVersionRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>> PrepareAsyncVersion(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>>(PrepareAsyncVersionRaw(context, request, cq));
    }
    // Tx exposes read-only transactions for the key-value store
    //
    // When tx open, client must receive 1 message from server with txID
    // When cursor open, client must receive 1 message from server with cursorID
    // Then only client can initiate messages from server
    std::unique_ptr< ::grpc::ClientReaderWriterInterface< ::remote::Cursor, ::remote::Pair>> Tx(::grpc::ClientContext* context) {
      return std::unique_ptr< ::grpc::ClientReaderWriterInterface< ::remote::Cursor, ::remote::Pair>>(TxRaw(context));
    }
    std::unique_ptr< ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>> AsyncTx(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>>(AsyncTxRaw(context, cq, tag));
    }
    std::unique_ptr< ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>> PrepareAsyncTx(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>>(PrepareAsyncTxRaw(context, cq));
    }
    std::unique_ptr< ::grpc::ClientReaderInterface< ::remote::StateChangeBatch>> StateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request) {
      return std::unique_ptr< ::grpc::ClientReaderInterface< ::remote::StateChangeBatch>>(StateChangesRaw(context, request));
    }
    std::unique_ptr< ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>> AsyncStateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq, void* tag) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>>(AsyncStateChangesRaw(context, request, cq, tag));
    }
    std::unique_ptr< ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>> PrepareAsyncStateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>>(PrepareAsyncStateChangesRaw(context, request, cq));
    }
    class async_interface {
     public:
      virtual ~async_interface() {}
      // Version returns the service version number
      virtual void Version(::grpc::ClientContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response, std::function<void(::grpc::Status)>) = 0;
      virtual void Version(::grpc::ClientContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response, ::grpc::ClientUnaryReactor* reactor) = 0;
      // Tx exposes read-only transactions for the key-value store
      //
      // When tx open, client must receive 1 message from server with txID
      // When cursor open, client must receive 1 message from server with cursorID
      // Then only client can initiate messages from server
      virtual void Tx(::grpc::ClientContext* context, ::grpc::ClientBidiReactor< ::remote::Cursor,::remote::Pair>* reactor) = 0;
      virtual void StateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest* request, ::grpc::ClientReadReactor< ::remote::StateChangeBatch>* reactor) = 0;
    };
    typedef class async_interface experimental_async_interface;
    virtual class async_interface* async() { return nullptr; }
    class async_interface* experimental_async() { return async(); }
   private:
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>* AsyncVersionRaw(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientAsyncResponseReaderInterface< ::types::VersionReply>* PrepareAsyncVersionRaw(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientReaderWriterInterface< ::remote::Cursor, ::remote::Pair>* TxRaw(::grpc::ClientContext* context) = 0;
    virtual ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>* AsyncTxRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) = 0;
    virtual ::grpc::ClientAsyncReaderWriterInterface< ::remote::Cursor, ::remote::Pair>* PrepareAsyncTxRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) = 0;
    virtual ::grpc::ClientReaderInterface< ::remote::StateChangeBatch>* StateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request) = 0;
    virtual ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>* AsyncStateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq, void* tag) = 0;
    virtual ::grpc::ClientAsyncReaderInterface< ::remote::StateChangeBatch>* PrepareAsyncStateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq) = 0;
  };
  class Stub final : public StubInterface {
   public:
    Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());
    ::grpc::Status Version(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::types::VersionReply* response) override;
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::types::VersionReply>> AsyncVersion(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::types::VersionReply>>(AsyncVersionRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::types::VersionReply>> PrepareAsyncVersion(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncResponseReader< ::types::VersionReply>>(PrepareAsyncVersionRaw(context, request, cq));
    }
    std::unique_ptr< ::grpc::ClientReaderWriter< ::remote::Cursor, ::remote::Pair>> Tx(::grpc::ClientContext* context) {
      return std::unique_ptr< ::grpc::ClientReaderWriter< ::remote::Cursor, ::remote::Pair>>(TxRaw(context));
    }
    std::unique_ptr<  ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>> AsyncTx(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>>(AsyncTxRaw(context, cq, tag));
    }
    std::unique_ptr<  ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>> PrepareAsyncTx(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>>(PrepareAsyncTxRaw(context, cq));
    }
    std::unique_ptr< ::grpc::ClientReader< ::remote::StateChangeBatch>> StateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request) {
      return std::unique_ptr< ::grpc::ClientReader< ::remote::StateChangeBatch>>(StateChangesRaw(context, request));
    }
    std::unique_ptr< ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>> AsyncStateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq, void* tag) {
      return std::unique_ptr< ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>>(AsyncStateChangesRaw(context, request, cq, tag));
    }
    std::unique_ptr< ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>> PrepareAsyncStateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq) {
      return std::unique_ptr< ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>>(PrepareAsyncStateChangesRaw(context, request, cq));
    }
    class async final :
      public StubInterface::async_interface {
     public:
      void Version(::grpc::ClientContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response, std::function<void(::grpc::Status)>) override;
      void Version(::grpc::ClientContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response, ::grpc::ClientUnaryReactor* reactor) override;
      void Tx(::grpc::ClientContext* context, ::grpc::ClientBidiReactor< ::remote::Cursor,::remote::Pair>* reactor) override;
      void StateChanges(::grpc::ClientContext* context, const ::remote::StateChangeRequest* request, ::grpc::ClientReadReactor< ::remote::StateChangeBatch>* reactor) override;
     private:
      friend class Stub;
      explicit async(Stub* stub): stub_(stub) { }
      Stub* stub() { return stub_; }
      Stub* stub_;
    };
    class async* async() override { return &async_stub_; }

   private:
    std::shared_ptr< ::grpc::ChannelInterface> channel_;
    class async async_stub_{this};
    ::grpc::ClientAsyncResponseReader< ::types::VersionReply>* AsyncVersionRaw(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientAsyncResponseReader< ::types::VersionReply>* PrepareAsyncVersionRaw(::grpc::ClientContext* context, const ::google::protobuf::Empty& request, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientReaderWriter< ::remote::Cursor, ::remote::Pair>* TxRaw(::grpc::ClientContext* context) override;
    ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>* AsyncTxRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) override;
    ::grpc::ClientAsyncReaderWriter< ::remote::Cursor, ::remote::Pair>* PrepareAsyncTxRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) override;
    ::grpc::ClientReader< ::remote::StateChangeBatch>* StateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request) override;
    ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>* AsyncStateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq, void* tag) override;
    ::grpc::ClientAsyncReader< ::remote::StateChangeBatch>* PrepareAsyncStateChangesRaw(::grpc::ClientContext* context, const ::remote::StateChangeRequest& request, ::grpc::CompletionQueue* cq) override;
    const ::grpc::internal::RpcMethod rpcmethod_Version_;
    const ::grpc::internal::RpcMethod rpcmethod_Tx_;
    const ::grpc::internal::RpcMethod rpcmethod_StateChanges_;
  };
  static std::unique_ptr<Stub> NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options = ::grpc::StubOptions());

  class Service : public ::grpc::Service {
   public:
    Service();
    virtual ~Service();
    // Version returns the service version number
    virtual ::grpc::Status Version(::grpc::ServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response);
    // Tx exposes read-only transactions for the key-value store
    //
    // When tx open, client must receive 1 message from server with txID
    // When cursor open, client must receive 1 message from server with cursorID
    // Then only client can initiate messages from server
    virtual ::grpc::Status Tx(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* stream);
    virtual ::grpc::Status StateChanges(::grpc::ServerContext* context, const ::remote::StateChangeRequest* request, ::grpc::ServerWriter< ::remote::StateChangeBatch>* writer);
  };
  template <class BaseClass>
  class WithAsyncMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_Version() {
      ::grpc::Service::MarkMethodAsync(0);
    }
    ~WithAsyncMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestVersion(::grpc::ServerContext* context, ::google::protobuf::Empty* request, ::grpc::ServerAsyncResponseWriter< ::types::VersionReply>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithAsyncMethod_Tx : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_Tx() {
      ::grpc::Service::MarkMethodAsync(1);
    }
    ~WithAsyncMethod_Tx() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Tx(::grpc::ServerContext* /*context*/, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* /*stream*/)  override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestTx(::grpc::ServerContext* context, ::grpc::ServerAsyncReaderWriter< ::remote::Pair, ::remote::Cursor>* stream, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncBidiStreaming(1, context, stream, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithAsyncMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithAsyncMethod_StateChanges() {
      ::grpc::Service::MarkMethodAsync(2);
    }
    ~WithAsyncMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestStateChanges(::grpc::ServerContext* context, ::remote::StateChangeRequest* request, ::grpc::ServerAsyncWriter< ::remote::StateChangeBatch>* writer, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncServerStreaming(2, context, request, writer, new_call_cq, notification_cq, tag);
    }
  };
  typedef WithAsyncMethod_Version<WithAsyncMethod_Tx<WithAsyncMethod_StateChanges<Service > > > AsyncService;
  template <class BaseClass>
  class WithCallbackMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_Version() {
      ::grpc::Service::MarkMethodCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::google::protobuf::Empty, ::types::VersionReply>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::google::protobuf::Empty* request, ::types::VersionReply* response) { return this->Version(context, request, response); }));}
    void SetMessageAllocatorFor_Version(
        ::grpc::MessageAllocator< ::google::protobuf::Empty, ::types::VersionReply>* allocator) {
      ::grpc::internal::MethodHandler* const handler = ::grpc::Service::GetHandler(0);
      static_cast<::grpc::internal::CallbackUnaryHandler< ::google::protobuf::Empty, ::types::VersionReply>*>(handler)
              ->SetMessageAllocator(allocator);
    }
    ~WithCallbackMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Version(
      ::grpc::CallbackServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithCallbackMethod_Tx : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_Tx() {
      ::grpc::Service::MarkMethodCallback(1,
          new ::grpc::internal::CallbackBidiHandler< ::remote::Cursor, ::remote::Pair>(
            [this](
                   ::grpc::CallbackServerContext* context) { return this->Tx(context); }));
    }
    ~WithCallbackMethod_Tx() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Tx(::grpc::ServerContext* /*context*/, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* /*stream*/)  override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerBidiReactor< ::remote::Cursor, ::remote::Pair>* Tx(
      ::grpc::CallbackServerContext* /*context*/)
      { return nullptr; }
  };
  template <class BaseClass>
  class WithCallbackMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithCallbackMethod_StateChanges() {
      ::grpc::Service::MarkMethodCallback(2,
          new ::grpc::internal::CallbackServerStreamingHandler< ::remote::StateChangeRequest, ::remote::StateChangeBatch>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::remote::StateChangeRequest* request) { return this->StateChanges(context, request); }));
    }
    ~WithCallbackMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerWriteReactor< ::remote::StateChangeBatch>* StateChanges(
      ::grpc::CallbackServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/)  { return nullptr; }
  };
  typedef WithCallbackMethod_Version<WithCallbackMethod_Tx<WithCallbackMethod_StateChanges<Service > > > CallbackService;
  typedef CallbackService ExperimentalCallbackService;
  template <class BaseClass>
  class WithGenericMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_Version() {
      ::grpc::Service::MarkMethodGeneric(0);
    }
    ~WithGenericMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithGenericMethod_Tx : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_Tx() {
      ::grpc::Service::MarkMethodGeneric(1);
    }
    ~WithGenericMethod_Tx() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Tx(::grpc::ServerContext* /*context*/, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* /*stream*/)  override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithGenericMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithGenericMethod_StateChanges() {
      ::grpc::Service::MarkMethodGeneric(2);
    }
    ~WithGenericMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
  };
  template <class BaseClass>
  class WithRawMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_Version() {
      ::grpc::Service::MarkMethodRaw(0);
    }
    ~WithRawMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestVersion(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncResponseWriter< ::grpc::ByteBuffer>* response, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncUnary(0, context, request, response, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawMethod_Tx : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_Tx() {
      ::grpc::Service::MarkMethodRaw(1);
    }
    ~WithRawMethod_Tx() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Tx(::grpc::ServerContext* /*context*/, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* /*stream*/)  override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestTx(::grpc::ServerContext* context, ::grpc::ServerAsyncReaderWriter< ::grpc::ByteBuffer, ::grpc::ByteBuffer>* stream, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncBidiStreaming(1, context, stream, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawMethod_StateChanges() {
      ::grpc::Service::MarkMethodRaw(2);
    }
    ~WithRawMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    void RequestStateChanges(::grpc::ServerContext* context, ::grpc::ByteBuffer* request, ::grpc::ServerAsyncWriter< ::grpc::ByteBuffer>* writer, ::grpc::CompletionQueue* new_call_cq, ::grpc::ServerCompletionQueue* notification_cq, void *tag) {
      ::grpc::Service::RequestAsyncServerStreaming(2, context, request, writer, new_call_cq, notification_cq, tag);
    }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_Version() {
      ::grpc::Service::MarkMethodRawCallback(0,
          new ::grpc::internal::CallbackUnaryHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const ::grpc::ByteBuffer* request, ::grpc::ByteBuffer* response) { return this->Version(context, request, response); }));
    }
    ~WithRawCallbackMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerUnaryReactor* Version(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/, ::grpc::ByteBuffer* /*response*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_Tx : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_Tx() {
      ::grpc::Service::MarkMethodRawCallback(1,
          new ::grpc::internal::CallbackBidiHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context) { return this->Tx(context); }));
    }
    ~WithRawCallbackMethod_Tx() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status Tx(::grpc::ServerContext* /*context*/, ::grpc::ServerReaderWriter< ::remote::Pair, ::remote::Cursor>* /*stream*/)  override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerBidiReactor< ::grpc::ByteBuffer, ::grpc::ByteBuffer>* Tx(
      ::grpc::CallbackServerContext* /*context*/)
      { return nullptr; }
  };
  template <class BaseClass>
  class WithRawCallbackMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithRawCallbackMethod_StateChanges() {
      ::grpc::Service::MarkMethodRawCallback(2,
          new ::grpc::internal::CallbackServerStreamingHandler< ::grpc::ByteBuffer, ::grpc::ByteBuffer>(
            [this](
                   ::grpc::CallbackServerContext* context, const::grpc::ByteBuffer* request) { return this->StateChanges(context, request); }));
    }
    ~WithRawCallbackMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable synchronous version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    virtual ::grpc::ServerWriteReactor< ::grpc::ByteBuffer>* StateChanges(
      ::grpc::CallbackServerContext* /*context*/, const ::grpc::ByteBuffer* /*request*/)  { return nullptr; }
  };
  template <class BaseClass>
  class WithStreamedUnaryMethod_Version : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithStreamedUnaryMethod_Version() {
      ::grpc::Service::MarkMethodStreamed(0,
        new ::grpc::internal::StreamedUnaryHandler<
          ::google::protobuf::Empty, ::types::VersionReply>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerUnaryStreamer<
                     ::google::protobuf::Empty, ::types::VersionReply>* streamer) {
                       return this->StreamedVersion(context,
                         streamer);
                  }));
    }
    ~WithStreamedUnaryMethod_Version() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status Version(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::VersionReply* /*response*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with streamed unary
    virtual ::grpc::Status StreamedVersion(::grpc::ServerContext* context, ::grpc::ServerUnaryStreamer< ::google::protobuf::Empty,::types::VersionReply>* server_unary_streamer) = 0;
  };
  typedef WithStreamedUnaryMethod_Version<Service > StreamedUnaryService;
  template <class BaseClass>
  class WithSplitStreamingMethod_StateChanges : public BaseClass {
   private:
    void BaseClassMustBeDerivedFromService(const Service* /*service*/) {}
   public:
    WithSplitStreamingMethod_StateChanges() {
      ::grpc::Service::MarkMethodStreamed(2,
        new ::grpc::internal::SplitServerStreamingHandler<
          ::remote::StateChangeRequest, ::remote::StateChangeBatch>(
            [this](::grpc::ServerContext* context,
                   ::grpc::ServerSplitStreamer<
                     ::remote::StateChangeRequest, ::remote::StateChangeBatch>* streamer) {
                       return this->StreamedStateChanges(context,
                         streamer);
                  }));
    }
    ~WithSplitStreamingMethod_StateChanges() override {
      BaseClassMustBeDerivedFromService(this);
    }
    // disable regular version of this method
    ::grpc::Status StateChanges(::grpc::ServerContext* /*context*/, const ::remote::StateChangeRequest* /*request*/, ::grpc::ServerWriter< ::remote::StateChangeBatch>* /*writer*/) override {
      abort();
      return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
    }
    // replace default version of method with split streamed
    virtual ::grpc::Status StreamedStateChanges(::grpc::ServerContext* context, ::grpc::ServerSplitStreamer< ::remote::StateChangeRequest,::remote::StateChangeBatch>* server_split_streamer) = 0;
  };
  typedef WithSplitStreamingMethod_StateChanges<Service > SplitStreamedService;
  typedef WithStreamedUnaryMethod_Version<WithSplitStreamingMethod_StateChanges<Service > > StreamedService;
};

}  // namespace remote


#endif  // GRPC_remote_2fkv_2eproto__INCLUDED
