// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: namespaces/namespaces.proto

// Protobuf Java Version: 3.25.2
package com.namespaces;

public interface UpdateNamespaceResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:namespaces.UpdateNamespaceResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return Whether the namespace field is set.
   */
  boolean hasNamespace();
  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return The namespace.
   */
  com.namespaces.Namespace getNamespace();
  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   */
  com.namespaces.NamespaceOrBuilder getNamespaceOrBuilder();
}