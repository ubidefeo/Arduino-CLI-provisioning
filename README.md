# cli-getting-started
Arduino IoT Cloud "Getting Started" via command line

Based off initial work by Luigi Gubello (@luigigubello).
Greatly influenced by Martino Facchin (@facchinm).

**NOTE:** 
Heavily tested on Mac OS and Linux

### Pre-requirements
* Python 3.5+
* You will need some Python modules. To install them run `pip install -r requirements.txt`
* Arduino CLI, install following [the instruction](https://arduino.github.io/arduino-cli/installation/)
* An Arduino board with ECCX08 Cryptographic Element
    - Arduino MKR 1000
    - Arduino MKR WiFi 1010
    - Arduino MKR GSM 1400
    - Arduino Nano 33 IoT
    - Arduino Nano RP2040 Connect
    - Arduino Portenta H7

### Usage
1. Go to [https://create.arduino.cc/iot/things](https://create.arduino.cc/iot/integrations) and generate the API Client ID and Secret ID.
The script looks for a configuration file in the user's home directory. This file, named `ArduinoIoTCloudAPI_credentials.json`, should contain your API Client ID and Secret ID as as follows
```json
{
"client_id": "XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx",
"secret_id": "XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx"
}
```
An example file is provided as part of this repository, to be filled and renamed by removing the `-example` part.
The script will also accept a `--api_credentials_file` parameter:
`python provisioning-helper.py --api_credentials_file /path/to/my/ArduinoIoTCloudAPI_credentials.json`

2. Connect your supported Arduino board to the computer and run `python provisioning-helper.py`. Pass in the options you deem necessary such as `--device_name` or `--api_credentials_file`

3. If you skip step 2 you will be asked to connect your board and try again

4. The script will query your board for a Provisioning Sketch ID and in case none is returned it will use ArduinoCLI to automatically upload the firmware required (`ProvisioningADVANCED`)

Available arguments to the script are visible by running `python provisioning-helper.py -h`.
You can specify a device name or have one generated for you based on timestamp.


This is a pre-development repo and will eventually be transferred to Arduino, please file issues for questions.

Ubi
