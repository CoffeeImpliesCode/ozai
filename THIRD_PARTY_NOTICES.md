# Third-party notices

First-party code is licensed under MIT; see [LICENSE](LICENSE). Third-party source and fixtures retain their own licenses.

## Components

| Component | Path(s) in this repository | License | Copyright holder(s) | Upstream |
|---|---|---|---|---|
| iroh 1.3.0 (`187f59e80afdae6bd9866002b33d3365c00b06d8`) | `src/base/ula.zig`; `src/discovery/{dns,item,lookup,lookup_io,pkarr,pkarr_services,preset,resolve,txt}.zig`; `src/endpoint/{endpoint,incoming_filter}.zig`; `src/net/{holepunch,holepunch_run,holepunch_trigger,probe,report}.zig`; `src/relay/{client,frame_decode,frame_encode,frame_roundtrip,frame_types,server,server_handshake,server_queue,server_registry}.zig`; `src/router/router.zig`; `src/transport/{addr_map,batch}.zig` | MIT (upstream MIT OR Apache-2.0; this port uses MIT) | Copyright 2025 N0, INC. | [n0-computer/iroh at commit](https://github.com/n0-computer/iroh/tree/187f59e80afdae6bd9866002b33d3365c00b06d8) |
| iroh-blobs 0.103.0 (`e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`) | `src/blobs/{protocol,range_spec,framing}.zig`; `src/ticket/blob_ticket.zig` | MIT (upstream MIT OR Apache-2.0; this port uses MIT) | Copyright 2023 N0, INC. | [n0-computer/iroh-blobs at commit](https://github.com/n0-computer/iroh-blobs/tree/e82cbdcbdac9a78033174aad55e3199b2cf4c0dc) |
| iroh-gossip 0.101.0 (`2885dd9f1120e46aca5acbcd7f212e4c64e278b9`) | `src/gossip/{codec,hyparview,plumtree}.zig`; `src/gossip/codec/tags.zig`; `src/gossip/fixtures/iroh-2885dd9/` | MIT (upstream MIT OR Apache-2.0; this port uses MIT) | Copyright 2023 N0, INC. | [n0-computer/iroh-gossip at commit](https://github.com/n0-computer/iroh-gossip/tree/2885dd9f1120e46aca5acbcd7f212e4c64e278b9) |
| Noq 1.3.0 (`c1f411562e6078852749b8bcf1190523096a107f` and `89ed00c31297c2127d1697a7b63983d60fd02ecb`) | `src/net/native_nat.zig` (first commit); `src/relay/frame_writer.zig`, `src/net/holepunch.zig`, `src/net/qad.zig`, `src/transport/batch.zig`, `src/transport/batch_opt.zig` (second commit) | MIT (upstream MIT OR Apache-2.0; this port uses MIT) | Copyright (c) 2018-2025 The quinn Developers; Copyright (c) 2025 N0, Inc. | [n0-computer/noq at first commit](https://github.com/n0-computer/noq/tree/c1f411562e6078852749b8bcf1190523096a107f); [second commit](https://github.com/n0-computer/noq/tree/89ed00c31297c2127d1697a7b63983d60fd02ecb) |
| quic-zig 0.5.0 (`14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719`) | `vendor/quic/` | MIT | Copyright (c) 2022, Endel Dreyer | [endel/quic-zig at commit](https://github.com/endel/quic-zig/tree/14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719); license text retained in [`vendor/quic/LICENSE`](vendor/quic/LICENSE) |

## MIT license texts

### iroh

Copyright 2025 N0, INC.

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

### iroh-blobs

Copyright 2023 N0, INC.

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

### iroh-gossip

Copyright 2023 N0, INC.

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

### Noq

Copyright (c) 2018-2025 The quinn Developers
Copyright (c) 2025 N0, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
