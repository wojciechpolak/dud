# Camera image fixtures for optical transfers

`camera-v40-format0.gray.gz` contains a 960 by 960 JPEG-derived luminance raster
with four QR symbols. Luminance is `(77R + 150G + 29B) >>> 8`, matching the
scanner. Only pixels inside the clockwise polygon `(53,47)`, `(893,40)`,
`(886,868)`, `(80,870)` are retained; every other pixel is white (`255`). The
symbol field keeps its camera perspective and compression artifacts. The
surrounding desktop and window title are excluded. The gzip stream has a zero
timestamp and contains no source filename or JPEG metadata. Test fixtures are
excluded from PWA assets.

`camera-v40-format0.frame.bin` contains the complete 2,952-byte frame recovered
from the top-left Version 40 L symbol. The native encoder reproduces every byte
from the deterministic `random-1mib.bin` corpus, session
`78f08696213a8cbc1581d345b30e2000`, stripe 0, sequence 813712 and a 2,860-byte
block. Scanner and worker tests compare the complete frame and verify format-0
rejection. The fixture establishes recovery of one frame from a four-symbol
camera raster, not phone performance or memory limits.

The gzip fixture SHA-256 is
`66812612bd000d1d1430028f2fe9c66c0bf10f94cfa79906b6998610de85dd1c`; the frame
SHA-256 is `7e3563e9d8406e917d3907ed038422d243dc55912666269a88225a55474b5e2e`.
The random corpus SHA-256 is
`d37e76900c3d428a369465fc53dcc162f11a848a731dd94dbfbfc40dbcf167a1`.

The fixture test pins both files' complete bytes; the worker tests enforce
scanner work bounds.
