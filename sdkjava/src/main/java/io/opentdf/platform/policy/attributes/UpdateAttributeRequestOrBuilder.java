// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.attributes;

public interface UpdateAttributeRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.attributes.UpdateAttributeRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.policy.attributes.AttributeCreateUpdate attribute = 2 [json_name = "attribute", (.buf.validate.field) = { ... }</code>
   * @return Whether the attribute field is set.
   */
  boolean hasAttribute();
  /**
   * <code>.policy.attributes.AttributeCreateUpdate attribute = 2 [json_name = "attribute", (.buf.validate.field) = { ... }</code>
   * @return The attribute.
   */
  io.opentdf.platform.policy.attributes.AttributeCreateUpdate getAttribute();
  /**
   * <code>.policy.attributes.AttributeCreateUpdate attribute = 2 [json_name = "attribute", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.attributes.AttributeCreateUpdateOrBuilder getAttributeOrBuilder();
}