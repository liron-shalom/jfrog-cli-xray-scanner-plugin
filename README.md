# xray-scanner

## About this plugin
This plugin uses JFrog Xray to scan local packages for security vulnerabilities and licenses.
The plugin wil search the package in Artifactory,
and if the package does not exist you can allow the plugin to upload the package in order to scan it.

## Installation with JFrog CLI
Installing the latest version:

`$ jfrog plugin install xray-scanner`

Installing a specific version:

`$ jfrog plugin install xray-scanner@version`

Uninstalling a plugin

`$ jfrog plugin uninstall hello-frog`

## Usage
### Commands
* scanner-config
    - An interactive command to configure xray-scanner
    - Example:
    ```
      $ jfrog xray-scanner scanner-config
     ```
* scan
    - Arguments:
        - path -  The local file system path to a package which should be scanned by Xray..
    - Flags:
        - security-only: Provide security scan result only. **[Default: false]**
        - license-only: Provide license scan result only. **[Default: false]**
        - min-severity: Minimum security vulnerability severity to present. **[Default: low]**
        - keep: Keep package in Artifactory if uploaded. **[Default: false]**
        - server-id: Artifactory server ID configured using the config command **[Optional]**

    - Example:
    ```
  $ jfrog xray-scanner scan  ./myApp.jar
  
  /Users/usr/myApp.jar does not exist in Artifactory.
  Xray-scanner will upload and scan the file.
  [Info] [Thread 0] Uploading artifact: /Users/usr/myApp.jar
  Waiting for Xray to scan the package.
  [Info] Searching artifacts...
  [Info] Found 1 artifact.
  [Info] [Thread 0] Deleting generic-local/myApp.jar
  Scan result for: /Users/usr/myApp.jar
  1. myApp.jar
  SHA256:74b63la0cdb1d4718e6807f2ed1015sc2f15a513910d68036af9a559196195e9
  
  LICENSES (1):
    1.Apache-2.0
  
  VULNERABILITIES (0):
  ```

## Additional info
None.

## Release Notes
The release notes are available [here](RELEASE.md).
