// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: storage/declarative_config_health.proto

package storage

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	types "github.com/gogo/protobuf/types"
	proto "github.com/golang/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type DeclarativeConfigHealth_Status int32

const (
	DeclarativeConfigHealth_UNHEALTHY DeclarativeConfigHealth_Status = 0
	DeclarativeConfigHealth_HEALTHY   DeclarativeConfigHealth_Status = 1
)

var DeclarativeConfigHealth_Status_name = map[int32]string{
	0: "UNHEALTHY",
	1: "HEALTHY",
}

var DeclarativeConfigHealth_Status_value = map[string]int32{
	"UNHEALTHY": 0,
	"HEALTHY":   1,
}

func (x DeclarativeConfigHealth_Status) String() string {
	return proto.EnumName(DeclarativeConfigHealth_Status_name, int32(x))
}

func (DeclarativeConfigHealth_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_671c3ab7741e96a4, []int{0, 0}
}

type DeclarativeConfigHealth_ResourceType int32

const (
	DeclarativeConfigHealth_CONFIG_MAP     DeclarativeConfigHealth_ResourceType = 0
	DeclarativeConfigHealth_ACCESS_SCOPE   DeclarativeConfigHealth_ResourceType = 1
	DeclarativeConfigHealth_PERMISSION_SET DeclarativeConfigHealth_ResourceType = 2
	DeclarativeConfigHealth_ROLE           DeclarativeConfigHealth_ResourceType = 3
	DeclarativeConfigHealth_AUTH_PROVIDER  DeclarativeConfigHealth_ResourceType = 4
	DeclarativeConfigHealth_GROUP          DeclarativeConfigHealth_ResourceType = 5
	DeclarativeConfigHealth_NOTIFIER       DeclarativeConfigHealth_ResourceType = 6
)

var DeclarativeConfigHealth_ResourceType_name = map[int32]string{
	0: "CONFIG_MAP",
	1: "ACCESS_SCOPE",
	2: "PERMISSION_SET",
	3: "ROLE",
	4: "AUTH_PROVIDER",
	5: "GROUP",
	6: "NOTIFIER",
}

var DeclarativeConfigHealth_ResourceType_value = map[string]int32{
	"CONFIG_MAP":     0,
	"ACCESS_SCOPE":   1,
	"PERMISSION_SET": 2,
	"ROLE":           3,
	"AUTH_PROVIDER":  4,
	"GROUP":          5,
	"NOTIFIER":       6,
}

func (x DeclarativeConfigHealth_ResourceType) String() string {
	return proto.EnumName(DeclarativeConfigHealth_ResourceType_name, int32(x))
}

func (DeclarativeConfigHealth_ResourceType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_671c3ab7741e96a4, []int{0, 1}
}

type DeclarativeConfigHealth struct {
	Id           string                               `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty" sql:"pk,type(uuid)"`
	Name         string                               `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Status       DeclarativeConfigHealth_Status       `protobuf:"varint,4,opt,name=status,proto3,enum=storage.DeclarativeConfigHealth_Status" json:"status,omitempty"`
	ErrorMessage string                               `protobuf:"bytes,5,opt,name=error_message,json=errorMessage,proto3" json:"error_message,omitempty"`
	ResourceName string                               `protobuf:"bytes,6,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
	ResourceType DeclarativeConfigHealth_ResourceType `protobuf:"varint,7,opt,name=resource_type,json=resourceType,proto3,enum=storage.DeclarativeConfigHealth_ResourceType" json:"resource_type,omitempty"`
	// Timestamp when the current status was set.
	LastTimestamp        *types.Timestamp `protobuf:"bytes,8,opt,name=last_timestamp,json=lastTimestamp,proto3" json:"last_timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{}         `json:"-"`
	XXX_unrecognized     []byte           `json:"-"`
	XXX_sizecache        int32            `json:"-"`
}

func (m *DeclarativeConfigHealth) Reset()         { *m = DeclarativeConfigHealth{} }
func (m *DeclarativeConfigHealth) String() string { return proto.CompactTextString(m) }
func (*DeclarativeConfigHealth) ProtoMessage()    {}
func (*DeclarativeConfigHealth) Descriptor() ([]byte, []int) {
	return fileDescriptor_671c3ab7741e96a4, []int{0}
}
func (m *DeclarativeConfigHealth) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DeclarativeConfigHealth) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DeclarativeConfigHealth.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DeclarativeConfigHealth) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeclarativeConfigHealth.Merge(m, src)
}
func (m *DeclarativeConfigHealth) XXX_Size() int {
	return m.Size()
}
func (m *DeclarativeConfigHealth) XXX_DiscardUnknown() {
	xxx_messageInfo_DeclarativeConfigHealth.DiscardUnknown(m)
}

var xxx_messageInfo_DeclarativeConfigHealth proto.InternalMessageInfo

func (m *DeclarativeConfigHealth) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *DeclarativeConfigHealth) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *DeclarativeConfigHealth) GetStatus() DeclarativeConfigHealth_Status {
	if m != nil {
		return m.Status
	}
	return DeclarativeConfigHealth_UNHEALTHY
}

func (m *DeclarativeConfigHealth) GetErrorMessage() string {
	if m != nil {
		return m.ErrorMessage
	}
	return ""
}

func (m *DeclarativeConfigHealth) GetResourceName() string {
	if m != nil {
		return m.ResourceName
	}
	return ""
}

func (m *DeclarativeConfigHealth) GetResourceType() DeclarativeConfigHealth_ResourceType {
	if m != nil {
		return m.ResourceType
	}
	return DeclarativeConfigHealth_CONFIG_MAP
}

func (m *DeclarativeConfigHealth) GetLastTimestamp() *types.Timestamp {
	if m != nil {
		return m.LastTimestamp
	}
	return nil
}

func (m *DeclarativeConfigHealth) MessageClone() proto.Message {
	return m.Clone()
}
func (m *DeclarativeConfigHealth) Clone() *DeclarativeConfigHealth {
	if m == nil {
		return nil
	}
	cloned := new(DeclarativeConfigHealth)
	*cloned = *m

	cloned.LastTimestamp = m.LastTimestamp.Clone()
	return cloned
}

func init() {
	proto.RegisterEnum("storage.DeclarativeConfigHealth_Status", DeclarativeConfigHealth_Status_name, DeclarativeConfigHealth_Status_value)
	proto.RegisterEnum("storage.DeclarativeConfigHealth_ResourceType", DeclarativeConfigHealth_ResourceType_name, DeclarativeConfigHealth_ResourceType_value)
	proto.RegisterType((*DeclarativeConfigHealth)(nil), "storage.DeclarativeConfigHealth")
}

func init() {
	proto.RegisterFile("storage/declarative_config_health.proto", fileDescriptor_671c3ab7741e96a4)
}

var fileDescriptor_671c3ab7741e96a4 = []byte{
	// 483 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xdf, 0x6e, 0xd3, 0x30,
	0x14, 0xc6, 0x9b, 0xd2, 0xbf, 0x67, 0x6d, 0x15, 0x0c, 0xd2, 0x42, 0x2f, 0xba, 0xaa, 0x20, 0xb5,
	0x48, 0x90, 0x4a, 0x83, 0x2b, 0x6e, 0x50, 0x97, 0x65, 0x6b, 0xa4, 0x35, 0x89, 0x9c, 0x14, 0x09,
	0x6e, 0x22, 0xaf, 0xf5, 0xb2, 0x68, 0xe9, 0x1c, 0x62, 0x07, 0x31, 0x9e, 0x04, 0xf1, 0x44, 0x5c,
	0xf2, 0x04, 0x08, 0x95, 0x37, 0xe0, 0x09, 0x50, 0x9c, 0x66, 0xdb, 0x0d, 0xe2, 0xee, 0x9c, 0x4f,
	0xbf, 0xe3, 0xef, 0xb3, 0x8f, 0x61, 0xcc, 0x05, 0x4b, 0x49, 0x48, 0xa7, 0x6b, 0xba, 0x8a, 0x49,
	0x4a, 0x44, 0xf4, 0x89, 0x06, 0x2b, 0x76, 0x7d, 0x11, 0x85, 0xc1, 0x25, 0x25, 0xb1, 0xb8, 0xd4,
	0x93, 0x94, 0x09, 0x86, 0x9a, 0x3b, 0xb0, 0x7f, 0x10, 0x32, 0x16, 0xc6, 0x74, 0x2a, 0xe5, 0xf3,
	0xec, 0x62, 0x2a, 0xa2, 0x0d, 0xe5, 0x82, 0x6c, 0x92, 0x82, 0xec, 0x3f, 0x0e, 0x59, 0xc8, 0x64,
	0x39, 0xcd, 0xab, 0x42, 0x1d, 0x7d, 0xab, 0xc1, 0xfe, 0xf1, 0x9d, 0x87, 0x21, 0x2d, 0xe6, 0xd2,
	0x01, 0x8d, 0xa1, 0x1a, 0xad, 0x35, 0x65, 0xa8, 0x4c, 0xda, 0x47, 0xfb, 0x7f, 0x7e, 0x1e, 0x3c,
	0xe2, 0x1f, 0xe3, 0x37, 0xa3, 0xe4, 0xea, 0x85, 0xb8, 0x49, 0xe8, 0x24, 0xcb, 0xa2, 0xf5, 0xf3,
	0x11, 0xae, 0x46, 0x6b, 0x84, 0xa0, 0x76, 0x4d, 0x36, 0x54, 0xab, 0xe6, 0x28, 0x96, 0x35, 0x7a,
	0x0b, 0x0d, 0x2e, 0x88, 0xc8, 0xb8, 0x56, 0x1b, 0x2a, 0x93, 0xde, 0xe1, 0x58, 0xdf, 0x25, 0xd5,
	0xff, 0x61, 0xa7, 0x7b, 0x12, 0xc7, 0xbb, 0x31, 0xf4, 0x14, 0xba, 0x34, 0x4d, 0x59, 0x1a, 0x6c,
	0x28, 0xe7, 0x24, 0xa4, 0x5a, 0x5d, 0x9e, 0xde, 0x91, 0xe2, 0xa2, 0xd0, 0x72, 0x28, 0xa5, 0x9c,
	0x65, 0xe9, 0x8a, 0x06, 0x32, 0x42, 0xa3, 0x80, 0x4a, 0xd1, 0xce, 0xa3, 0xe0, 0x7b, 0x50, 0x1e,
	0x5d, 0x6b, 0xca, 0x44, 0x2f, 0xff, 0x9b, 0x08, 0xef, 0xa6, 0xfc, 0x9b, 0x84, 0xde, 0x9d, 0x99,
	0x77, 0x68, 0x06, 0xbd, 0x98, 0x70, 0x11, 0xdc, 0xbe, 0xb2, 0xd6, 0x1a, 0x2a, 0x93, 0xbd, 0xc3,
	0xbe, 0x5e, 0xec, 0x41, 0x2f, 0xf7, 0xa0, 0xfb, 0x25, 0x81, 0xbb, 0xf9, 0xc4, 0x6d, 0x3b, 0x7a,
	0x06, 0x8d, 0xe2, 0xca, 0xa8, 0x0b, 0xed, 0xa5, 0x3d, 0x37, 0x67, 0x67, 0xfe, 0xfc, 0xbd, 0x5a,
	0x41, 0x7b, 0xd0, 0x2c, 0x1b, 0x65, 0xf4, 0x05, 0x3a, 0xf7, 0x63, 0xa0, 0x1e, 0x80, 0xe1, 0xd8,
	0x27, 0xd6, 0x69, 0xb0, 0x98, 0xb9, 0x6a, 0x05, 0xa9, 0xd0, 0x99, 0x19, 0x86, 0xe9, 0x79, 0x81,
	0x67, 0x38, 0xae, 0xa9, 0x2a, 0x08, 0x41, 0xcf, 0x35, 0xf1, 0xc2, 0xf2, 0x3c, 0xcb, 0xb1, 0x03,
	0xcf, 0xf4, 0xd5, 0x2a, 0x6a, 0x41, 0x0d, 0x3b, 0x67, 0xa6, 0xfa, 0x00, 0x3d, 0x84, 0xee, 0x6c,
	0xe9, 0xcf, 0x03, 0x17, 0x3b, 0xef, 0xac, 0x63, 0x13, 0xab, 0x35, 0xd4, 0x86, 0xfa, 0x29, 0x76,
	0x96, 0xae, 0x5a, 0x47, 0x1d, 0x68, 0xd9, 0x8e, 0x6f, 0x9d, 0x58, 0x26, 0x56, 0x1b, 0x47, 0xaf,
	0xbf, 0x6f, 0x07, 0xca, 0x8f, 0xed, 0x40, 0xf9, 0xb5, 0x1d, 0x28, 0x5f, 0x7f, 0x0f, 0x2a, 0xf0,
	0x24, 0x62, 0x3a, 0x17, 0x64, 0x75, 0x95, 0xb2, 0xcf, 0xc5, 0x15, 0xcb, 0x47, 0xfc, 0x50, 0xfe,
	0xc4, 0xf3, 0x86, 0xd4, 0x5f, 0xfd, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x1b, 0x88, 0x5b, 0xed, 0xc4,
	0x02, 0x00, 0x00,
}

func (m *DeclarativeConfigHealth) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DeclarativeConfigHealth) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DeclarativeConfigHealth) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.LastTimestamp != nil {
		{
			size, err := m.LastTimestamp.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x42
	}
	if m.ResourceType != 0 {
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(m.ResourceType))
		i--
		dAtA[i] = 0x38
	}
	if len(m.ResourceName) > 0 {
		i -= len(m.ResourceName)
		copy(dAtA[i:], m.ResourceName)
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(len(m.ResourceName)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.ErrorMessage) > 0 {
		i -= len(m.ErrorMessage)
		copy(dAtA[i:], m.ErrorMessage)
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(len(m.ErrorMessage)))
		i--
		dAtA[i] = 0x2a
	}
	if m.Status != 0 {
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(m.Status))
		i--
		dAtA[i] = 0x20
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintDeclarativeConfigHealth(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintDeclarativeConfigHealth(dAtA []byte, offset int, v uint64) int {
	offset -= sovDeclarativeConfigHealth(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *DeclarativeConfigHealth) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovDeclarativeConfigHealth(uint64(l))
	}
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovDeclarativeConfigHealth(uint64(l))
	}
	if m.Status != 0 {
		n += 1 + sovDeclarativeConfigHealth(uint64(m.Status))
	}
	l = len(m.ErrorMessage)
	if l > 0 {
		n += 1 + l + sovDeclarativeConfigHealth(uint64(l))
	}
	l = len(m.ResourceName)
	if l > 0 {
		n += 1 + l + sovDeclarativeConfigHealth(uint64(l))
	}
	if m.ResourceType != 0 {
		n += 1 + sovDeclarativeConfigHealth(uint64(m.ResourceType))
	}
	if m.LastTimestamp != nil {
		l = m.LastTimestamp.Size()
		n += 1 + l + sovDeclarativeConfigHealth(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovDeclarativeConfigHealth(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozDeclarativeConfigHealth(x uint64) (n int) {
	return sovDeclarativeConfigHealth(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DeclarativeConfigHealth) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDeclarativeConfigHealth
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: DeclarativeConfigHealth: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DeclarativeConfigHealth: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			m.Status = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Status |= DeclarativeConfigHealth_Status(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ErrorMessage", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ErrorMessage = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResourceName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ResourceName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResourceType", wireType)
			}
			m.ResourceType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ResourceType |= DeclarativeConfigHealth_ResourceType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LastTimestamp", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.LastTimestamp == nil {
				m.LastTimestamp = &types.Timestamp{}
			}
			if err := m.LastTimestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDeclarativeConfigHealth(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthDeclarativeConfigHealth
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipDeclarativeConfigHealth(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDeclarativeConfigHealth
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowDeclarativeConfigHealth
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthDeclarativeConfigHealth
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupDeclarativeConfigHealth
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthDeclarativeConfigHealth
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthDeclarativeConfigHealth        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDeclarativeConfigHealth          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupDeclarativeConfigHealth = fmt.Errorf("proto: unexpected end of group")
)
