# Fermyon Platform Plugin

A [Spin plugin](https://github.com/fermyon/spin-plugins) for interacting with the Fermyon self-hosted Platform from the [Spin CLI](https://github.com/fermyon/spin).

## Installing the latest plugin

```sh
spin plugin install --url https://github.com/fermyon/platform-plugin/releases/download/canary/platform.json
```

## Building and installing local changes

1. Package the plugin.

    ```sh
    cargo build --release
    cp target/release/platform-plugin platform
    tar -czvf platform.tar.gz platform
    sha256sum platform.tar.gz
    rm platform
    # Outputs a shasum to add to platform.json
    ```

1. Get the manifest.

    ```sh
    curl -LRO https://github.com/fermyon/platform-plugin/releases/download/canary/platform.json
    ```

1. Update the manifest to modify the `url` field to point to the path to local package (i.e. `"url": "file:///path/to/platform-plugin/plugin/platform.tar.gz"`) and update the shasum.

1. Install the plugin, pointing to the path to the manifest.

    ```sh
    spin plugin install -f ./plugin/platform.json
    ```

1. Run the plugin.

    ```sh
    spin platform --help
    ```
