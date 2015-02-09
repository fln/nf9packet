nf9packet
=========

This is golang library for NetFlow v9 packet decoding. It can be used to create
NetFlow v9 packet inspection and analysis tools, NetFlow collectors or higher
level libraries.

This package does only packet decoding in a single packet context. It keeps no
state when decoding multiple packets. As a result Data FlowSets can not be
decoded during initial packet decoding. To decode Data FlowSets user must keep
track of all seen Template Records and Options Template Records and then decode
Data FlowSets manually.

Most of structure names and comments are taken directly from RFC 3954. Reading
the NetFlow v9 protocol specification is highly recommended before using this
package.
