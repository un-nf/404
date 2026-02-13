# 404 v1.1 - Keystore & Documentation

> 404 no longer writes the CA key file to disk in plaintext on most OSes.

## MkDocs

404 now has an [official documentation page](https://un-nf.github.io/404-docs/)! It offers a more in guide depth for setup, maintenance, and functionality of 404. 

This website is being actively developed. Core functionality and guides are setup, but this is just a shell of what it should end up being. As of now, it is a polished conglomeration of the most useful documentation that was previously scattered across the repository. 

This documentation page will be rapidly changing, but feel free to open a [pull request](https://github.com/un-nf/404-docs) if you see something obvious, or even if you just want to help with stylization!

## Windows

On Windows, 404 utilizes the Windows Data Protection API (DPAPI) to securely encrypt the generated `.key` file. The `.crt` file remains plaintext on disk.

## macOS

On macOS, 404 utilizes the native Keychain Services API (via the `keyring` crate) to securely store credentials in the system keychain instead of writing them to disk.

## Configuration

Users can configure keystore behavior via the `keystore` configuration section in `src/STATIC_proxy/config/static.example.toml` or your `.toml` config file:
- **mode**: `file` (default) or `keychain`
- **service**: Service name for OS keychains (default: `404.static_proxy`)
- **account**: Account name for OS keychains (default: `ca_key`)
- **fallback_path**: Optional fallback file path for backward compatibility

For backward compatibility, the default mode remains `file` storage on non-keychain systems.
