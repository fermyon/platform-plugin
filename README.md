# Fermyon Platform Plugin

A [Spin plugin](https://github.com/fermyon/spin-plugins) for interacting with the [Fermyon self-hosted Platform](https://github.com/fermyon/installer) from the [Spin CLI](https://github.com/fermyon/spin).

## Installing the latest plugin

```sh
spin plugin install --url https://github.com/fermyon/platform-plugin/releases/download/canary/platform.json
```

## Building and installing local changes

1. Install `spin pluginify`

    ```sh
    spin plugins update
    spin plugins install pluginify --yes
    ```

2. Build, package and install the plugin.

    ```sh
    cargo build --release
    spin pluginify --install
    ```

3. Run the plugin.

    ```sh
    spin platform --help
    ```
