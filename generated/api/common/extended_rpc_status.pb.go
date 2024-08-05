// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v4.25.3
// source: api/common/extended_rpc_status.proto

package common

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The `Status` type defines a logical error model that is suitable for
// different programming environments, including REST APIs and RPC APIs.
type ExtendedRpcStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// A simple error code that can be easily handled by the client. The
	// actual error code is defined by `google.rpc.Code`.
	Code int32 `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	// A developer-facing human-readable error message in English. It should
	// both explain the error and offer an actionable resolution to it.
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	// Additional error information that the client code can use to handle
	// the error, such as retry info or a help link.
	Details []*anypb.Any `protobuf:"bytes,3,rep,name=details,proto3" json:"details,omitempty"`
	// Backward compatibility to gRPC Gateway V1 returned error payload.
	// It contains the same string returned in "message" field.
	//
	// Deprecated: Marked as deprecated in api/common/extended_rpc_status.proto.
	Error string `protobuf:"bytes,4,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *ExtendedRpcStatus) Reset() {
	*x = ExtendedRpcStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_common_extended_rpc_status_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExtendedRpcStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExtendedRpcStatus) ProtoMessage() {}

func (x *ExtendedRpcStatus) ProtoReflect() protoreflect.Message {
	mi := &file_api_common_extended_rpc_status_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExtendedRpcStatus.ProtoReflect.Descriptor instead.
func (*ExtendedRpcStatus) Descriptor() ([]byte, []int) {
	return file_api_common_extended_rpc_status_proto_rawDescGZIP(), []int{0}
}

func (x *ExtendedRpcStatus) GetCode() int32 {
	if x != nil {
		return x.Code
	}
	return 0
}

func (x *ExtendedRpcStatus) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *ExtendedRpcStatus) GetDetails() []*anypb.Any {
	if x != nil {
		return x.Details
	}
	return nil
}

// Deprecated: Marked as deprecated in api/common/extended_rpc_status.proto.
func (x *ExtendedRpcStatus) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

var File_api_common_extended_rpc_status_proto protoreflect.FileDescriptor

var file_api_common_extended_rpc_status_proto_rawDesc = []byte{
	0x0a, 0x24, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x1a, 0x19,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8b, 0x01, 0x0a, 0x11, 0x45, 0x78,
	0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x52, 0x70, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x04, 0x63,
	0x6f, 0x64, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2e, 0x0a,
	0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x41, 0x6e, 0x79, 0x52, 0x07, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x18, 0x0a,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01,
	0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x42, 0x33, 0x0a, 0x1c, 0x69, 0x6f, 0x2e, 0x73, 0x74,
	0x61, 0x63, 0x6b, 0x72, 0x6f, 0x78, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5a, 0x13, 0x2e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x3b, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_common_extended_rpc_status_proto_rawDescOnce sync.Once
	file_api_common_extended_rpc_status_proto_rawDescData = file_api_common_extended_rpc_status_proto_rawDesc
)

func file_api_common_extended_rpc_status_proto_rawDescGZIP() []byte {
	file_api_common_extended_rpc_status_proto_rawDescOnce.Do(func() {
		file_api_common_extended_rpc_status_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_common_extended_rpc_status_proto_rawDescData)
	})
	return file_api_common_extended_rpc_status_proto_rawDescData
}

var file_api_common_extended_rpc_status_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_common_extended_rpc_status_proto_goTypes = []any{
	(*ExtendedRpcStatus)(nil), // 0: common.ExtendedRpcStatus
	(*anypb.Any)(nil),         // 1: google.protobuf.Any
}
var file_api_common_extended_rpc_status_proto_depIdxs = []int32{
	1, // 0: common.ExtendedRpcStatus.details:type_name -> google.protobuf.Any
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_common_extended_rpc_status_proto_init() }
func file_api_common_extended_rpc_status_proto_init() {
	if File_api_common_extended_rpc_status_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_common_extended_rpc_status_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ExtendedRpcStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_common_extended_rpc_status_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_common_extended_rpc_status_proto_goTypes,
		DependencyIndexes: file_api_common_extended_rpc_status_proto_depIdxs,
		MessageInfos:      file_api_common_extended_rpc_status_proto_msgTypes,
	}.Build()
	File_api_common_extended_rpc_status_proto = out.File
	file_api_common_extended_rpc_status_proto_rawDesc = nil
	file_api_common_extended_rpc_status_proto_goTypes = nil
	file_api_common_extended_rpc_status_proto_depIdxs = nil
}