// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: policy/resourcemapping/resource_mapping.proto

package resourcemapping

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	ResourceMappingService_ListResourceMappings_FullMethodName  = "/policy.resourcemapping.ResourceMappingService/ListResourceMappings"
	ResourceMappingService_GetResourceMapping_FullMethodName    = "/policy.resourcemapping.ResourceMappingService/GetResourceMapping"
	ResourceMappingService_CreateResourceMapping_FullMethodName = "/policy.resourcemapping.ResourceMappingService/CreateResourceMapping"
	ResourceMappingService_UpdateResourceMapping_FullMethodName = "/policy.resourcemapping.ResourceMappingService/UpdateResourceMapping"
	ResourceMappingService_DeleteResourceMapping_FullMethodName = "/policy.resourcemapping.ResourceMappingService/DeleteResourceMapping"
)

// ResourceMappingServiceClient is the client API for ResourceMappingService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ResourceMappingServiceClient interface {
	// Request Example:
	// - empty body
	//
	// Response Example:
	// {
	// "resource_mappings": [
	// {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// ]
	// }
	ListResourceMappings(ctx context.Context, in *ListResourceMappingsRequest, opts ...grpc.CallOption) (*ListResourceMappingsResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	GetResourceMapping(ctx context.Context, in *GetResourceMappingRequest, opts ...grpc.CallOption) (*GetResourceMappingResponse, error)
	// Request Example:
	// {
	// "resource_mapping": {
	// "attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ]
	// }
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	CreateResourceMapping(ctx context.Context, in *CreateResourceMappingRequest, opts ...grpc.CallOption) (*CreateResourceMappingResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "resource_mapping": {
	// "attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// "NEWTERM"
	// ]
	// }
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	UpdateResourceMapping(ctx context.Context, in *UpdateResourceMappingRequest, opts ...grpc.CallOption) (*UpdateResourceMappingResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	DeleteResourceMapping(ctx context.Context, in *DeleteResourceMappingRequest, opts ...grpc.CallOption) (*DeleteResourceMappingResponse, error)
}

type resourceMappingServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewResourceMappingServiceClient(cc grpc.ClientConnInterface) ResourceMappingServiceClient {
	return &resourceMappingServiceClient{cc}
}

func (c *resourceMappingServiceClient) ListResourceMappings(ctx context.Context, in *ListResourceMappingsRequest, opts ...grpc.CallOption) (*ListResourceMappingsResponse, error) {
	out := new(ListResourceMappingsResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_ListResourceMappings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) GetResourceMapping(ctx context.Context, in *GetResourceMappingRequest, opts ...grpc.CallOption) (*GetResourceMappingResponse, error) {
	out := new(GetResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_GetResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) CreateResourceMapping(ctx context.Context, in *CreateResourceMappingRequest, opts ...grpc.CallOption) (*CreateResourceMappingResponse, error) {
	out := new(CreateResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_CreateResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) UpdateResourceMapping(ctx context.Context, in *UpdateResourceMappingRequest, opts ...grpc.CallOption) (*UpdateResourceMappingResponse, error) {
	out := new(UpdateResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_UpdateResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *resourceMappingServiceClient) DeleteResourceMapping(ctx context.Context, in *DeleteResourceMappingRequest, opts ...grpc.CallOption) (*DeleteResourceMappingResponse, error) {
	out := new(DeleteResourceMappingResponse)
	err := c.cc.Invoke(ctx, ResourceMappingService_DeleteResourceMapping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceMappingServiceServer is the server API for ResourceMappingService service.
// All implementations must embed UnimplementedResourceMappingServiceServer
// for forward compatibility
type ResourceMappingServiceServer interface {
	// Request Example:
	// - empty body
	//
	// Response Example:
	// {
	// "resource_mappings": [
	// {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// ]
	// }
	ListResourceMappings(context.Context, *ListResourceMappingsRequest) (*ListResourceMappingsResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	GetResourceMapping(context.Context, *GetResourceMappingRequest) (*GetResourceMappingResponse, error)
	// Request Example:
	// {
	// "resource_mapping": {
	// "attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ]
	// }
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	CreateResourceMapping(context.Context, *CreateResourceMappingRequest) (*CreateResourceMappingResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "resource_mapping": {
	// "attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// "NEWTERM"
	// ]
	// }
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	UpdateResourceMapping(context.Context, *UpdateResourceMappingRequest) (*UpdateResourceMappingResponse, error)
	// Request Example:
	// {
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
	// }
	//
	// Response Example:
	// {
	// "resource_mapping": {
	// "terms": [
	// "TOPSECRET",
	// "TS",
	// ],
	// "id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
	// "metadata": {
	// "labels": [],
	// "created_at": {
	// "seconds": "1706103276",
	// "nanos": 510718000
	// },
	// "updated_at": {
	// "seconds": "1706107873",
	// "nanos": 399786000
	// },
	// "description": ""
	// },
	// "attribute_value": {
	// "members": [],
	// "id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
	// "metadata": null,
	// "attribute_id": "",
	// "value": "value1"
	// }
	// }
	// }
	DeleteResourceMapping(context.Context, *DeleteResourceMappingRequest) (*DeleteResourceMappingResponse, error)
	mustEmbedUnimplementedResourceMappingServiceServer()
}

// UnimplementedResourceMappingServiceServer must be embedded to have forward compatible implementations.
type UnimplementedResourceMappingServiceServer struct {
}

func (UnimplementedResourceMappingServiceServer) ListResourceMappings(context.Context, *ListResourceMappingsRequest) (*ListResourceMappingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListResourceMappings not implemented")
}
func (UnimplementedResourceMappingServiceServer) GetResourceMapping(context.Context, *GetResourceMappingRequest) (*GetResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) CreateResourceMapping(context.Context, *CreateResourceMappingRequest) (*CreateResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) UpdateResourceMapping(context.Context, *UpdateResourceMappingRequest) (*UpdateResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) DeleteResourceMapping(context.Context, *DeleteResourceMappingRequest) (*DeleteResourceMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteResourceMapping not implemented")
}
func (UnimplementedResourceMappingServiceServer) mustEmbedUnimplementedResourceMappingServiceServer() {
}

// UnsafeResourceMappingServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ResourceMappingServiceServer will
// result in compilation errors.
type UnsafeResourceMappingServiceServer interface {
	mustEmbedUnimplementedResourceMappingServiceServer()
}

func RegisterResourceMappingServiceServer(s grpc.ServiceRegistrar, srv ResourceMappingServiceServer) {
	s.RegisterService(&ResourceMappingService_ServiceDesc, srv)
}

func _ResourceMappingService_ListResourceMappings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListResourceMappingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).ListResourceMappings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_ListResourceMappings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).ListResourceMappings(ctx, req.(*ListResourceMappingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_GetResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).GetResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_GetResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).GetResourceMapping(ctx, req.(*GetResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_CreateResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).CreateResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_CreateResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).CreateResourceMapping(ctx, req.(*CreateResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_UpdateResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).UpdateResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_UpdateResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).UpdateResourceMapping(ctx, req.(*UpdateResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ResourceMappingService_DeleteResourceMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteResourceMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ResourceMappingServiceServer).DeleteResourceMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ResourceMappingService_DeleteResourceMapping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ResourceMappingServiceServer).DeleteResourceMapping(ctx, req.(*DeleteResourceMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ResourceMappingService_ServiceDesc is the grpc.ServiceDesc for ResourceMappingService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ResourceMappingService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "policy.resourcemapping.ResourceMappingService",
	HandlerType: (*ResourceMappingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListResourceMappings",
			Handler:    _ResourceMappingService_ListResourceMappings_Handler,
		},
		{
			MethodName: "GetResourceMapping",
			Handler:    _ResourceMappingService_GetResourceMapping_Handler,
		},
		{
			MethodName: "CreateResourceMapping",
			Handler:    _ResourceMappingService_CreateResourceMapping_Handler,
		},
		{
			MethodName: "UpdateResourceMapping",
			Handler:    _ResourceMappingService_UpdateResourceMapping_Handler,
		},
		{
			MethodName: "DeleteResourceMapping",
			Handler:    _ResourceMappingService_DeleteResourceMapping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "policy/resourcemapping/resource_mapping.proto",
}
