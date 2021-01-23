// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: checkmate.proto

package checkmate

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ScanType int32

const (
	ScanType_PATH_SCAN   ScanType = 0
	ScanType_STRING_SCAN ScanType = 1
)

// Enum value maps for ScanType.
var (
	ScanType_name = map[int32]string{
		0: "PATH_SCAN",
		1: "STRING_SCAN",
	}
	ScanType_value = map[string]int32{
		"PATH_SCAN":   0,
		"STRING_SCAN": 1,
	}
)

func (x ScanType) Enum() *ScanType {
	p := new(ScanType)
	*p = x
	return p
}

func (x ScanType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ScanType) Descriptor() protoreflect.EnumDescriptor {
	return file_checkmate_proto_enumTypes[0].Descriptor()
}

func (ScanType) Type() protoreflect.EnumType {
	return &file_checkmate_proto_enumTypes[0]
}

func (x ScanType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ScanType.Descriptor instead.
func (ScanType) EnumDescriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{0}
}

type PluginMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Plugin ID
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Plugin display name
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// A display description
	Description string `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	// filesystem path of the plugin
	Path string `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
}

func (x *PluginMetadata) Reset() {
	*x = PluginMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PluginMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PluginMetadata) ProtoMessage() {}

func (x *PluginMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PluginMetadata.ProtoReflect.Descriptor instead.
func (*PluginMetadata) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{0}
}

func (x *PluginMetadata) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *PluginMetadata) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *PluginMetadata) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *PluginMetadata) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{1}
}

type DataToScan struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source     string `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	SourceType string `protobuf:"bytes,2,opt,name=source_type,json=sourceType,proto3" json:"source_type,omitempty"`
	Base64     bool   `protobuf:"varint,3,opt,name=base64,proto3" json:"base64,omitempty"`
}

func (x *DataToScan) Reset() {
	*x = DataToScan{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DataToScan) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DataToScan) ProtoMessage() {}

func (x *DataToScan) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DataToScan.ProtoReflect.Descriptor instead.
func (*DataToScan) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{2}
}

func (x *DataToScan) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *DataToScan) GetSourceType() string {
	if x != nil {
		return x.SourceType
	}
	return ""
}

func (x *DataToScan) GetBase64() bool {
	if x != nil {
		return x.Base64
	}
	return false
}

type StringList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value []string `protobuf:"bytes,1,rep,name=value,proto3" json:"value,omitempty"`
}

func (x *StringList) Reset() {
	*x = StringList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StringList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StringList) ProtoMessage() {}

func (x *StringList) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StringList.ProtoReflect.Descriptor instead.
func (*StringList) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{3}
}

func (x *StringList) GetValue() []string {
	if x != nil {
		return x.Value
	}
	return nil
}

// ExcludeDefinition is the structure for conveying excluded values definitions
type ExcludeDefinition struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GloballyExcludedRegExs  []string               `protobuf:"bytes,1,rep,name=globally_excluded_reg_exs,json=globallyExcludedRegExs,proto3" json:"globally_excluded_reg_exs,omitempty"`
	GloballyExcludedStrings []string               `protobuf:"bytes,2,rep,name=globally_excluded_strings,json=globallyExcludedStrings,proto3" json:"globally_excluded_strings,omitempty"`
	PathExclusionRegExs     []string               `protobuf:"bytes,3,rep,name=path_exclusion_reg_exs,json=pathExclusionRegExs,proto3" json:"path_exclusion_reg_exs,omitempty"`
	PerFileExcludedStrings  map[string]*StringList `protobuf:"bytes,4,rep,name=per_file_excluded_strings,json=perFileExcludedStrings,proto3" json:"per_file_excluded_strings,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	PathRegexExcludedRegExs map[string]*StringList `protobuf:"bytes,5,rep,name=path_regex_excluded_reg_exs,json=pathRegexExcludedRegExs,proto3" json:"path_regex_excluded_reg_exs,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ExcludeDefinition) Reset() {
	*x = ExcludeDefinition{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExcludeDefinition) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExcludeDefinition) ProtoMessage() {}

func (x *ExcludeDefinition) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExcludeDefinition.ProtoReflect.Descriptor instead.
func (*ExcludeDefinition) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{4}
}

func (x *ExcludeDefinition) GetGloballyExcludedRegExs() []string {
	if x != nil {
		return x.GloballyExcludedRegExs
	}
	return nil
}

func (x *ExcludeDefinition) GetGloballyExcludedStrings() []string {
	if x != nil {
		return x.GloballyExcludedStrings
	}
	return nil
}

func (x *ExcludeDefinition) GetPathExclusionRegExs() []string {
	if x != nil {
		return x.PathExclusionRegExs
	}
	return nil
}

func (x *ExcludeDefinition) GetPerFileExcludedStrings() map[string]*StringList {
	if x != nil {
		return x.PerFileExcludedStrings
	}
	return nil
}

func (x *ExcludeDefinition) GetPathRegexExcludedRegExs() map[string]*StringList {
	if x != nil {
		return x.PathRegexExcludedRegExs
	}
	return nil
}

type ScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScanType ScanType `protobuf:"varint,1,opt,name=scan_type,json=scanType,proto3,enum=checkmate.ScanType" json:"scan_type,omitempty"`
	// used for PATH_SCAN request type
	PathsToScan []string `protobuf:"bytes,2,rep,name=paths_to_scan,json=pathsToScan,proto3" json:"paths_to_scan,omitempty"`
	// used for STRING_SCAN request type
	DataToScan []*DataToScan `protobuf:"bytes,3,rep,name=data_to_scan,json=dataToScan,proto3" json:"data_to_scan,omitempty"`
	// excludes
	Excludes *ExcludeDefinition `protobuf:"bytes,4,opt,name=excludes,proto3" json:"excludes,omitempty"`
	// show source code evidence where possible
	ShowSource            bool `protobuf:"varint,5,opt,name=show_source,json=showSource,proto3" json:"show_source,omitempty"`
	ConfidentialFilesOnly bool `protobuf:"varint,6,opt,name=confidential_files_only,json=confidentialFilesOnly,proto3" json:"confidential_files_only,omitempty"`
	CalculateChecksum     bool `protobuf:"varint,7,opt,name=calculate_checksum,json=calculateChecksum,proto3" json:"calculate_checksum,omitempty"`
}

func (x *ScanRequest) Reset() {
	*x = ScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_checkmate_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanRequest) ProtoMessage() {}

func (x *ScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_checkmate_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanRequest.ProtoReflect.Descriptor instead.
func (*ScanRequest) Descriptor() ([]byte, []int) {
	return file_checkmate_proto_rawDescGZIP(), []int{5}
}

func (x *ScanRequest) GetScanType() ScanType {
	if x != nil {
		return x.ScanType
	}
	return ScanType_PATH_SCAN
}

func (x *ScanRequest) GetPathsToScan() []string {
	if x != nil {
		return x.PathsToScan
	}
	return nil
}

func (x *ScanRequest) GetDataToScan() []*DataToScan {
	if x != nil {
		return x.DataToScan
	}
	return nil
}

func (x *ScanRequest) GetExcludes() *ExcludeDefinition {
	if x != nil {
		return x.Excludes
	}
	return nil
}

func (x *ScanRequest) GetShowSource() bool {
	if x != nil {
		return x.ShowSource
	}
	return false
}

func (x *ScanRequest) GetConfidentialFilesOnly() bool {
	if x != nil {
		return x.ConfidentialFilesOnly
	}
	return false
}

func (x *ScanRequest) GetCalculateChecksum() bool {
	if x != nil {
		return x.CalculateChecksum
	}
	return false
}

var File_checkmate_proto protoreflect.FileDescriptor

var file_checkmate_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x1a, 0x11, 0x64, 0x69,
	0x61, 0x67, 0x6e, 0x6f, 0x73, 0x74, 0x69, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x6a, 0x0a, 0x0e, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x22, 0x07, 0x0a, 0x05, 0x45,
	0x6d, 0x70, 0x74, 0x79, 0x22, 0x5d, 0x0a, 0x0a, 0x44, 0x61, 0x74, 0x61, 0x54, 0x6f, 0x53, 0x63,
	0x61, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x62,
	0x61, 0x73, 0x65, 0x36, 0x34, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x62, 0x61, 0x73,
	0x65, 0x36, 0x34, 0x22, 0x22, 0x0a, 0x0a, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4c, 0x69, 0x73,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0xf2, 0x04, 0x0a, 0x11, 0x45, 0x78, 0x63, 0x6c,
	0x75, 0x64, 0x65, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x39, 0x0a,
	0x19, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x6c, 0x79, 0x5f, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x64, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x65, 0x78, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x16, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x6c, 0x79, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x64, 0x52, 0x65, 0x67, 0x45, 0x78, 0x73, 0x12, 0x3a, 0x0a, 0x19, 0x67, 0x6c, 0x6f, 0x62,
	0x61, 0x6c, 0x6c, 0x79, 0x5f, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x5f, 0x73, 0x74,
	0x72, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x17, 0x67, 0x6c, 0x6f,
	0x62, 0x61, 0x6c, 0x6c, 0x79, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x53, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x73, 0x12, 0x33, 0x0a, 0x16, 0x70, 0x61, 0x74, 0x68, 0x5f, 0x65, 0x78, 0x63,
	0x6c, 0x75, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x65, 0x78, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x13, 0x70, 0x61, 0x74, 0x68, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x73,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x67, 0x45, 0x78, 0x73, 0x12, 0x73, 0x0a, 0x19, 0x70, 0x65, 0x72,
	0x5f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x5f, 0x73,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x63,
	0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65,
	0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x50, 0x65, 0x72, 0x46, 0x69,
	0x6c, 0x65, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x16, 0x70, 0x65, 0x72, 0x46, 0x69, 0x6c, 0x65, 0x45,
	0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x77,
	0x0a, 0x1b, 0x70, 0x61, 0x74, 0x68, 0x5f, 0x72, 0x65, 0x67, 0x65, 0x78, 0x5f, 0x65, 0x78, 0x63,
	0x6c, 0x75, 0x64, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x67, 0x5f, 0x65, 0x78, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x39, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e,
	0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x50, 0x61, 0x74, 0x68, 0x52, 0x65, 0x67, 0x65, 0x78, 0x45, 0x78, 0x63, 0x6c, 0x75,
	0x64, 0x65, 0x64, 0x52, 0x65, 0x67, 0x45, 0x78, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x17,
	0x70, 0x61, 0x74, 0x68, 0x52, 0x65, 0x67, 0x65, 0x78, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65,
	0x64, 0x52, 0x65, 0x67, 0x45, 0x78, 0x73, 0x1a, 0x60, 0x0a, 0x1b, 0x50, 0x65, 0x72, 0x46, 0x69,
	0x6c, 0x65, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2b, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d,
	0x61, 0x74, 0x65, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4c, 0x69, 0x73, 0x74, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x61, 0x0a, 0x1c, 0x50, 0x61, 0x74,
	0x68, 0x52, 0x65, 0x67, 0x65, 0x78, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x52, 0x65,
	0x67, 0x45, 0x78, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2b, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63, 0x68, 0x65,
	0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x4c, 0x69, 0x73,
	0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xde, 0x02, 0x0a,
	0x0b, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x30, 0x0a, 0x09,
	0x73, 0x63, 0x61, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x13, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x53, 0x63, 0x61, 0x6e,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x08, 0x73, 0x63, 0x61, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22,
	0x0a, 0x0d, 0x70, 0x61, 0x74, 0x68, 0x73, 0x5f, 0x74, 0x6f, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x70, 0x61, 0x74, 0x68, 0x73, 0x54, 0x6f, 0x53, 0x63,
	0x61, 0x6e, 0x12, 0x37, 0x0a, 0x0c, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x74, 0x6f, 0x5f, 0x73, 0x63,
	0x61, 0x6e, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b,
	0x6d, 0x61, 0x74, 0x65, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x54, 0x6f, 0x53, 0x63, 0x61, 0x6e, 0x52,
	0x0a, 0x64, 0x61, 0x74, 0x61, 0x54, 0x6f, 0x53, 0x63, 0x61, 0x6e, 0x12, 0x38, 0x0a, 0x08, 0x65,
	0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x65, 0x78, 0x63,
	0x6c, 0x75, 0x64, 0x65, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x68, 0x6f, 0x77, 0x5f, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x73, 0x68, 0x6f, 0x77,
	0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x36, 0x0a, 0x17, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x5f, 0x6f, 0x6e, 0x6c,
	0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x15, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x2d,
	0x0a, 0x12, 0x63, 0x61, 0x6c, 0x63, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x5f, 0x63, 0x68, 0x65, 0x63,
	0x6b, 0x73, 0x75, 0x6d, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x63, 0x61, 0x6c, 0x63,
	0x75, 0x6c, 0x61, 0x74, 0x65, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x2a, 0x2a, 0x0a,
	0x08, 0x53, 0x63, 0x61, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x50, 0x41, 0x54,
	0x48, 0x5f, 0x53, 0x43, 0x41, 0x4e, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x54, 0x52, 0x49,
	0x4e, 0x47, 0x5f, 0x53, 0x43, 0x41, 0x4e, 0x10, 0x01, 0x32, 0x92, 0x01, 0x0a, 0x0d, 0x50, 0x6c,
	0x75, 0x67, 0x69, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x40, 0x0a, 0x11, 0x47,
	0x65, 0x74, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x12, 0x10, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x19, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x50,
	0x6c, 0x75, 0x67, 0x69, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x3f, 0x0a,
	0x04, 0x53, 0x63, 0x61, 0x6e, 0x12, 0x16, 0x2e, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74,
	0x65, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1d, 0x2e,
	0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x2e, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69,
	0x74, 0x79, 0x44, 0x69, 0x61, 0x67, 0x6e, 0x6f, 0x73, 0x74, 0x69, 0x63, 0x30, 0x01, 0x42, 0x0d,
	0x5a, 0x0b, 0x2e, 0x3b, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x6d, 0x61, 0x74, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_checkmate_proto_rawDescOnce sync.Once
	file_checkmate_proto_rawDescData = file_checkmate_proto_rawDesc
)

func file_checkmate_proto_rawDescGZIP() []byte {
	file_checkmate_proto_rawDescOnce.Do(func() {
		file_checkmate_proto_rawDescData = protoimpl.X.CompressGZIP(file_checkmate_proto_rawDescData)
	})
	return file_checkmate_proto_rawDescData
}

var file_checkmate_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_checkmate_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_checkmate_proto_goTypes = []interface{}{
	(ScanType)(0),              // 0: checkmate.ScanType
	(*PluginMetadata)(nil),     // 1: checkmate.PluginMetadata
	(*Empty)(nil),              // 2: checkmate.Empty
	(*DataToScan)(nil),         // 3: checkmate.DataToScan
	(*StringList)(nil),         // 4: checkmate.StringList
	(*ExcludeDefinition)(nil),  // 5: checkmate.ExcludeDefinition
	(*ScanRequest)(nil),        // 6: checkmate.ScanRequest
	nil,                        // 7: checkmate.ExcludeDefinition.PerFileExcludedStringsEntry
	nil,                        // 8: checkmate.ExcludeDefinition.PathRegexExcludedRegExsEntry
	(*SecurityDiagnostic)(nil), // 9: checkmate.SecurityDiagnostic
}
var file_checkmate_proto_depIdxs = []int32{
	7, // 0: checkmate.ExcludeDefinition.per_file_excluded_strings:type_name -> checkmate.ExcludeDefinition.PerFileExcludedStringsEntry
	8, // 1: checkmate.ExcludeDefinition.path_regex_excluded_reg_exs:type_name -> checkmate.ExcludeDefinition.PathRegexExcludedRegExsEntry
	0, // 2: checkmate.ScanRequest.scan_type:type_name -> checkmate.ScanType
	3, // 3: checkmate.ScanRequest.data_to_scan:type_name -> checkmate.DataToScan
	5, // 4: checkmate.ScanRequest.excludes:type_name -> checkmate.ExcludeDefinition
	4, // 5: checkmate.ExcludeDefinition.PerFileExcludedStringsEntry.value:type_name -> checkmate.StringList
	4, // 6: checkmate.ExcludeDefinition.PathRegexExcludedRegExsEntry.value:type_name -> checkmate.StringList
	2, // 7: checkmate.PluginService.GetPluginMetadata:input_type -> checkmate.Empty
	6, // 8: checkmate.PluginService.Scan:input_type -> checkmate.ScanRequest
	1, // 9: checkmate.PluginService.GetPluginMetadata:output_type -> checkmate.PluginMetadata
	9, // 10: checkmate.PluginService.Scan:output_type -> checkmate.SecurityDiagnostic
	9, // [9:11] is the sub-list for method output_type
	7, // [7:9] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_checkmate_proto_init() }
func file_checkmate_proto_init() {
	if File_checkmate_proto != nil {
		return
	}
	file_diagnostics_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_checkmate_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PluginMetadata); i {
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
		file_checkmate_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
		file_checkmate_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DataToScan); i {
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
		file_checkmate_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StringList); i {
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
		file_checkmate_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExcludeDefinition); i {
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
		file_checkmate_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanRequest); i {
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
			RawDescriptor: file_checkmate_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_checkmate_proto_goTypes,
		DependencyIndexes: file_checkmate_proto_depIdxs,
		EnumInfos:         file_checkmate_proto_enumTypes,
		MessageInfos:      file_checkmate_proto_msgTypes,
	}.Build()
	File_checkmate_proto = out.File
	file_checkmate_proto_rawDesc = nil
	file_checkmate_proto_goTypes = nil
	file_checkmate_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// PluginServiceClient is the client API for PluginService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PluginServiceClient interface {
	GetPluginMetadata(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*PluginMetadata, error)
	Scan(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (PluginService_ScanClient, error)
}

type pluginServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPluginServiceClient(cc grpc.ClientConnInterface) PluginServiceClient {
	return &pluginServiceClient{cc}
}

func (c *pluginServiceClient) GetPluginMetadata(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*PluginMetadata, error) {
	out := new(PluginMetadata)
	err := c.cc.Invoke(ctx, "/checkmate.PluginService/GetPluginMetadata", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) Scan(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (PluginService_ScanClient, error) {
	stream, err := c.cc.NewStream(ctx, &_PluginService_serviceDesc.Streams[0], "/checkmate.PluginService/Scan", opts...)
	if err != nil {
		return nil, err
	}
	x := &pluginServiceScanClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type PluginService_ScanClient interface {
	Recv() (*SecurityDiagnostic, error)
	grpc.ClientStream
}

type pluginServiceScanClient struct {
	grpc.ClientStream
}

func (x *pluginServiceScanClient) Recv() (*SecurityDiagnostic, error) {
	m := new(SecurityDiagnostic)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// PluginServiceServer is the server API for PluginService service.
type PluginServiceServer interface {
	GetPluginMetadata(context.Context, *Empty) (*PluginMetadata, error)
	Scan(*ScanRequest, PluginService_ScanServer) error
}

// UnimplementedPluginServiceServer can be embedded to have forward compatible implementations.
type UnimplementedPluginServiceServer struct {
}

func (*UnimplementedPluginServiceServer) GetPluginMetadata(context.Context, *Empty) (*PluginMetadata, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPluginMetadata not implemented")
}
func (*UnimplementedPluginServiceServer) Scan(*ScanRequest, PluginService_ScanServer) error {
	return status.Errorf(codes.Unimplemented, "method Scan not implemented")
}

func RegisterPluginServiceServer(s *grpc.Server, srv PluginServiceServer) {
	s.RegisterService(&_PluginService_serviceDesc, srv)
}

func _PluginService_GetPluginMetadata_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).GetPluginMetadata(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/checkmate.PluginService/GetPluginMetadata",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).GetPluginMetadata(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_Scan_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ScanRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PluginServiceServer).Scan(m, &pluginServiceScanServer{stream})
}

type PluginService_ScanServer interface {
	Send(*SecurityDiagnostic) error
	grpc.ServerStream
}

type pluginServiceScanServer struct {
	grpc.ServerStream
}

func (x *pluginServiceScanServer) Send(m *SecurityDiagnostic) error {
	return x.ServerStream.SendMsg(m)
}

var _PluginService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "checkmate.PluginService",
	HandlerType: (*PluginServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPluginMetadata",
			Handler:    _PluginService_GetPluginMetadata_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Scan",
			Handler:       _PluginService_Scan_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "checkmate.proto",
}
