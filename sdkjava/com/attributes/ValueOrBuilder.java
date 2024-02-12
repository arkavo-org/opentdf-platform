// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package com.attributes;

public interface ValueOrBuilder extends
    // @@protoc_insertion_point(interface_extends:attributes.Value)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * generated uuid in database
   * </pre>
   *
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <pre>
   * generated uuid in database
   * </pre>
   *
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  com.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   */
  com.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <code>string attribute_id = 3 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The attributeId.
   */
  java.lang.String getAttributeId();
  /**
   * <code>string attribute_id = 3 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The bytes for attributeId.
   */
  com.google.protobuf.ByteString
      getAttributeIdBytes();

  /**
   * <code>string value = 4 [json_name = "value"];</code>
   * @return The value.
   */
  java.lang.String getValue();
  /**
   * <code>string value = 4 [json_name = "value"];</code>
   * @return The bytes for value.
   */
  com.google.protobuf.ByteString
      getValueBytes();

  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 5 [json_name = "members"];</code>
   * @return A list containing the members.
   */
  java.util.List<java.lang.String>
      getMembersList();
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 5 [json_name = "members"];</code>
   * @return The count of members.
   */
  int getMembersCount();
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 5 [json_name = "members"];</code>
   * @param index The index of the element to return.
   * @return The members at the given index.
   */
  java.lang.String getMembers(int index);
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 5 [json_name = "members"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the members at the given index.
   */
  com.google.protobuf.ByteString
      getMembersBytes(int index);

  /**
   * <pre>
   * list of key access servers
   * </pre>
   *
   * <code>repeated .kasregistry.KeyAccessServer grants = 6 [json_name = "grants"];</code>
   */
  java.util.List<com.kasregistry.KeyAccessServer> 
      getGrantsList();
  /**
   * <pre>
   * list of key access servers
   * </pre>
   *
   * <code>repeated .kasregistry.KeyAccessServer grants = 6 [json_name = "grants"];</code>
   */
  com.kasregistry.KeyAccessServer getGrants(int index);
  /**
   * <pre>
   * list of key access servers
   * </pre>
   *
   * <code>repeated .kasregistry.KeyAccessServer grants = 6 [json_name = "grants"];</code>
   */
  int getGrantsCount();
  /**
   * <pre>
   * list of key access servers
   * </pre>
   *
   * <code>repeated .kasregistry.KeyAccessServer grants = 6 [json_name = "grants"];</code>
   */
  java.util.List<? extends com.kasregistry.KeyAccessServerOrBuilder> 
      getGrantsOrBuilderList();
  /**
   * <pre>
   * list of key access servers
   * </pre>
   *
   * <code>repeated .kasregistry.KeyAccessServer grants = 6 [json_name = "grants"];</code>
   */
  com.kasregistry.KeyAccessServerOrBuilder getGrantsOrBuilder(
      int index);
}
