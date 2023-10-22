# exocdn

For now, we have to build on nightly to abort on panic.

### A high performance (I hope) CDN and DRM server

Both modules support TLS, http/2 and brotli/deflate/gzip/zstd compression. Makes use of all CPU threads.

http/2 is enabled automatically if TLS is configured.

#### CDN:

File paths are calculated from the file's blake3 hash and look the following way:

``{ip}:{port}/cdn/request/{blake3 hash}/{filename}``

Hashes are calculated in parallel on each program startup (no auto refresh for now).

#### DRM:

Requests have to be POST and be in application/x-www-form-urlencoded format.
Each request has to contain `token` (configured in the config file) and `file` (filename relative to the configured DRM
content directory)

``{ip}:{port}/drm/request``

If a request with an invalid token is made, the DRM can be configured to return an arbitrary file.