# Optical transfer format-1 vectors

These fixtures implement [dud/optical/1](../../../../docs/protocol-optical.md).
`npm run check:optical:vectors` regenerates Go and TypeScript files, compares
each with its committed bytes and then compares both languages with only
`generatedBy` excluded. Both profiles, stripe boundaries, selections, complete
frames and rejection codes are covered. JSON `format` is the vector schema
version; byte 8 of each frame is the wire version.

The format0 sibling directory carries immutable rejection fixtures. Parser
compatibility tests reject those frames. SHA-256 checks pin their bytes, the
independent QR oracles and the receiver camera images independently of
optical-format acceptance.
