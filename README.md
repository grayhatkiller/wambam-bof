# wambam-bof

A Cobalt Strike BOF that extracts access tokens from `.tbres` files. This BOF locates DPAPI-encrypted blobs stored in `.tbres` files, decrypts them in the current user context using `CryptUnprotectData`, and extracts the access token. This BOF is opsec safe and could be used as an alternate to office_tokens BOF. Since it avoids touching other process's memory, it could fly under the radar to retrieve access tokens. This is not a new technique [@xpn](https://x.com/_xpn_) has already done research on `.tbres` files.

### Usage
Compile the bof with `make` and load the wambam.cna file into Cobalt Strike.
1. Run the `wambam` command on beacon, it will automatically find the .tbres file and decrypt the DPAPI encrypted blob

---

**Note:** Decryption works only under the user context that originally encrypted the blob.

## References
This tool is a BOF version of the [@xpn](https://x.com/_xpn_) research of wambam.
- https://blog.xpnsec.com/wam-bam/
- https://github.com/xpn/WAMBam