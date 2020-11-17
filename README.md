# cli-getting-started
Arduino IoT Cloud "Getting Started" via command line

Based off initial work by Luigi Gubello (@luigigubello).
Greatly influenced by Martino Facchin (@facchinm).

**NOTE:** Because of how Windows tends to rename Serial ports when you don't look at it, it is advised to manually upload the `ProvisioningADVANCED` sketch rather than letting the Python script do that automatically.
Works well on Mac OS and Linux assuming you have the required components

### Pre-requirements
* Python 3.x
* You will need some Python modules. To install them run `pip install -r requirements.txt`
* Arduino CLI, install following [the instruction](https://arduino.github.io/arduino-cli/installation/)
* Install the following libraries for Arduino using the `arduino-cli lib install <lib_name>` (e.g.: `arduino-cli lib install ucrc16lib`)
    - `ucrc16lib`
    - `ArduinoIoTCloud`
    - `ArduinoECCX08`
* An Arduino board with ECCX08 Cryptographic Element

### Usage
1. Go to [https://create.arduino.cc/iot/things](https://create.arduino.cc/iot/things) and generate the API Client ID and Secret ID.
   The script expects a configuration file to exist in the user's home directory. This file, named `arduinoIoTCloudAPI.json`, should contain your API Client ID and Secret ID as as follows
```json
{
"client_id": "XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx",
"secret_id": "XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx"
}
```
2. Connect your Arduino board to your computer and run `python provisioning-helper.py`
3. If you skip step 3 you will be asked to connect your board
4. The script will query your board for a Sketch ID and in case none is returned it will use Arduino CLI to automatically upload the firmware required (`ProvisioningADVANCED`)

Available arguments to the script are viewed by running `python provisioning-helper.py -h`.
You can specify a device name or have one generated for you based on timestamp.
The script expects a configuration file in the user home named `arduinoIoTCloudAPI.json` containing your Client ID and Secret ID as follows. A configuration file can be manually entered as an argument using the flag `-api_credentials_file`


This is a fresh repo and will eventually be transferred to Arduino, please file issues for questions.

Ubi
