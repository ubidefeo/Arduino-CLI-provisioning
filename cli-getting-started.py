# x 0: python sends deviceName (from stdin) to API and gets deviceID
# √ 1: python requests CSR from Arduino - adds deviceID to payload
# √ 2: Arduino generates the csr
	# √ 2a: generate SHA256 (32B) using ECCx08
		# ECCX08cert.h: 199
		#   br_sha256_init(&sha256Context);
		#   br_sha256_update(&sha256Context, csrInfo, csrInfoHeaderLen + csrInfoLen);
		#   br_sha256_out(&sha256Context, csrInfoSha256);
		#   
		#   SHA256 is stored into csrInfoSha256
	# 2b: the 64 bytes are streamed back to Python
# 3: Python sends CSR to API and obtains the final certificate
# 4: Python sends final certificate to Arduino
# 5: Arduino does !ECCX08Cert.beginStorage

only_serial = False
exclude_cli_start = True

import requests
import getpass
import json
import serial.tools.list_ports
import serial
import time
import subprocess
import crcmod
import os

from enum import Enum, auto
import os
home = os.path.expanduser('~')
print(home)



PROVISIONING_SKETCH_RESPONSE = [0x55, 0xaa, 0x01, 0x01, 0xff, 0xaa, 0x55]
MAX_SERIAL_BUFFER = 128
MIN_MESSAGE_LENGTH = 10

_CRC_FUNC = crcmod.mkCrcFun(0x11021, initCrc=0, xorOut=0xffff)

CRC16_SIZE = 2
msg_start = [0x55, 0xaa]
msg_end = [0xaa, 0x55]

deviceCSR = []
device_id = ""

# MESSAGES
class MESSAGE_TYPE(Enum):
	NONE = 0
	COMMAND = auto()
	DATA = auto()
	RESPONSE = auto()

# COMMANDS
class COMMAND(Enum):
	GET_SKETCH_INFO = 1
	GET_CSR = auto()
	SET_LOCKED = auto()
	GET_LOCKED = auto()
	WRITE_CRYPTO = auto()
	BEGIN_STORAGE = auto()
	SET_DEVICE_ID = auto()
	SET_YEAR = auto()
	SET_MONTH = auto()
	SET_DAY = auto()
	SET_HOUR = auto()
	SET_VALIDITY = auto()
	SET_CERT_SERIAL = auto()
	SET_AUTH_KEY = auto()
	SET_SIGNATURE = auto()
	END_STORAGE = auto()

class ERROR(Enum):
	NONE = 0
	SYNC = auto()
	LOCK_FAIL = auto()
	LOCK_SUCCESS = auto()
	WRITE_CONFIG_FAIL = auto()
	CRC_FAIL = auto()
	CSR_GEN_FAIL = auto()
	CSR_GEN_SUCCESS = auto()
	SKETCH_UNKNOWN = auto()
	GENERIC = auto()
	ERROR_NO_DATA = auto();

def compose_message(msg_type, msg_payload):
	print(f"type {msg_type}")
	formed_message = bytearray(msg_start)
	formed_message.append(msg_type)
	payload_size = len(msg_payload) + CRC16_SIZE

	print(f"data size >>> {len(msg_payload)}")
	payload_size_L = (payload_size.to_bytes(2, "big"))[1]
	payload_size_H = (payload_size.to_bytes(2, "big"))[0]
	print(f"{hex(payload_size_H)} - {hex(payload_size_L)}")

	formed_message.append(payload_size_H)
	formed_message.append(payload_size_L)
	formed_message += bytearray(msg_payload)
	crc = _CRC_FUNC(bytearray(msg_payload))
	print(hex(crc))
	formed_message.append(((crc >> 8) & 0xff))
	formed_message.append(crc & 0xff)
	formed_message += bytearray(msg_end)
	print(f"msg payload: {msg_payload}")
	print(f"formed message: {formed_message}")
	return formed_message


	
def parse_response_data(r_data, failure_error):
	if(len(r_data) < 1):
		return ERROR.GENERIC
	msg_type = r_data[2]
	msg_length = r_data[3] << 8 | r_data[4]
	print(f"incoming data length: {msg_length}")
	payload_bytes = (r_data[5:][:msg_length - CRC16_SIZE])
	#print(payload_bytes)
	payload_computed_CRC = _CRC_FUNC(bytearray(payload_bytes))
	print(f"computed CRC: {hex(payload_computed_CRC)}")
	payload_received_CRC = r_data[len(r_data) - 4] << 8 | r_data[len(r_data) - 3]	
	print(f"received CRC: {hex(payload_received_CRC)}")
	if(payload_computed_CRC == payload_received_CRC):
		return payload_bytes;
	else:
		return failure_error


def send_command(command, payload = bytearray([]), encode = False, verbose_message = "it worked"):
	msg_payload = []
	msg_payload.append(command)

	if(encode):
		msg_payload += list(bytearray(payload.encode()))
	else:
		msg_payload += list(bytearray(payload))

	serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
	time.sleep(3)
	response_data = []

	while(serial_port.in_waiting > 0):
		response_data.append(int.from_bytes(serial_port.read(), "little"))

	print(response_data)

	parsed_response = parse_response_data(response_data, ERROR.CRC_FAIL)
	print(f"{command} response: {parsed_response}")
	if(parsed_response != ERROR.CRC_FAIL):
		print(f"ACK: {verbose_message}")
	#	certificate = send_csr(token, csr, device_id)
	else:
		print("data corrupted")
		print("Please relaunch the script to retry")



def generate_token(client_id, secret_id):
	url = 'https://api2.arduino.cc/iot/v1/clients/token'
	headers = {'content-type': 'application/x-www-form-urlencoded'}
	data = {'grant_type': 'client_credentials',
			'client_id': client_id,
			'client_secret': secret_id,
			'audience': 'https://api2.arduino.cc/iot'
			}
	response = requests.post(url, headers=headers, data=data)
	token = json.loads(response.text)['access_token']
	return token

def add_device(token, device_name, fqbn, type, serial):
	url = 'http://api2.arduino.cc/iot/v2/devices'
	headers = {'content-type': 'application/x-www-form-urlencoded',
			   'Authorization': 'Bearer ' + token
			   }
	data = {'fqbn': fqbn,
			'name': device_name,
			'type': type,
			'serial': serial
			}
	response = requests.put(url, headers=headers, data=data)
	device_id = json.loads(response.text)['id']
	return device_id

# this is the function to concatenate the DEVICE UID and Certificate
def send_csr(token, csr, device_id):
	url = 'http://api2.arduino.cc/iot/v2/devices/' + device_id + '/certs'
	headers = {'content-type': 'application/json',
			   'Authorization': 'Bearer ' + token
			   }
	data_cert = {'ca': 'Arduino',
			'csr': csr,
			'enabled': True
			}
	response = requests.put(url, headers=headers, data=json.dumps(data_cert))
	certificate = json.loads(response.text)['compressed']
	return certificate

def board_detection(port):
	if port.pid in [int('0x8057', 16), int('0x0057', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'nano_33_iot', 'fqbn': 'arduino:samd:nano_33_iot', 'serial_number': port.serial_number}
	elif port.pid in [int('0x804e', 16), int('0x004e', 16), int('0x824e', 16), int('0x024e', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkr1000', 'fqbn': 'arduino:samd:mkr1000', 'serial_number': port.serial_number}
	elif port.pid in [int('0x8054', 16), int('0x0054', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkrwifi1010', 'fqbn': 'arduino:samd:mkrwifi1010', 'serial_number': port.serial_number}
	elif port.pid in [int('0x8052', 16), int('0x0052', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkrgsm1400', 'fqbn': 'arduino:samd:mkrgsm1400', 'serial_number': port.serial_number}
	elif port.pid in [int('0x8055', 16), int('0x0055', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkrnb1500', 'fqbn': 'arduino:samd:mkrnb1500', 'serial_number': port.serial_number}
	elif port.pid in [int('0x8053', 16), int('0x0053', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkrwan1300', 'fqbn': 'arduino:samd:mkrwan1300', 'serial_number': port.serial_number}
	elif port.pid in [int('0x8059', 16), int('0x0059', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'mkrwan1310', 'fqbn': 'arduino:samd:mkrwan1310', 'serial_number': port.serial_number}
	else:
		return None

def find_device():
	device_list = []
	i = 0
	while len(device_list) != 1:
		for port in serial.tools.list_ports.comports():
			if port.vid == 9025:
				board_found = board_detection(port)
				if board_found != None:
					print('{} found'.format(board_found['board_name']))
					device_list.append(board_found)
		if device_list == [] and i != 1:
			print('Connect your Arduino!')
			i = 1
		if len(device_list) > 1 and i != 2:
			print('Please keep only one board')
			i = 2
			device_list = []
	return device_list

# client_id = getpass.getpass('Client ID:')
# secret_id = getpass.getpass('Secret ID:')

tmp_serial_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
#print(len(tmp_serial_data))
#compose_message(MESSAGE_TYPE.DATA.value, tmp_serial_data)

time.sleep(.4);

client_id = "cKFMPSmpgX75JSepVXMoe57TqzVu1rI4" #input('Client ID:')
secret_id = "KqJznij7YI5wqqzvQ1kszP6ciqI3cEQ3IKrUA6t0htoHcw82jnS26dhkyBwOEHJf" #input('Secret ID:')

device_name = f"Z{time.time()}_testdevice" #input('Device name: ')

device_list = find_device()

if not only_serial:
	token = generate_token(client_id, secret_id)
	device_id = add_device(token, device_name, device_list[0]['fqbn'], device_list[0]['type'], device_list[0]['serial_number'])
	print(f"device_id: {device_id}")

def get_sketch_info():
	print('Querying Crypto Provisioning Sketch...')
	print('Waiting for response...')
	msg_payload = []
	msg_payload.append(COMMAND.GET_SKETCH_INFO.value)
	print(msg_payload)
	serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
	time.sleep(.5)

	wait_for_message = True;
	response_data = []

	while(serial_port.in_waiting > 0):
		response_data.append(int.from_bytes(serial_port.read(), "little"))

	print(response_data)
	# print(PROVISIONING_SKETCH_RESPONSE)
	if(len(response_data) < MIN_MESSAGE_LENGTH):
		return ERROR.SKETCH_UNKNOWN
	parsed_response = parse_response_data(response_data, ERROR.SKETCH_UNKNOWN)
	return parsed_response
	

def install_sketch():
	print("Installing SAMD core")
	installing_core = subprocess.Popen(["arduino-cli","core","install","arduino:samd"], stdout=subprocess.PIPE)
	installing_core.wait()
	print("Installing ArduinoIoTCloud library")
	installing_lib = subprocess.Popen(["arduino-cli","lib","install","ArduinoIoTCloud"], stdout=subprocess.PIPE)
	installing_lib.wait()
	print("Compiling and Uploading ProvisioningADVANCED")
	compiling_sketch = subprocess.Popen(["arduino-cli","compile","ProvisioningADVANCED","-b", device_list[0]['fqbn'], "-u", "-p", device_list[0]['board_port']], stdout=subprocess.PIPE)
	compiling_sketch.wait()
	# print("Uploading Provisioning")
	# uploading_sketch = subprocess.Popen(["arduino-cli","upload","Provisioning","-b", device_list[0]['fqbn'], "-p", device_list[0]['board_port']], stdout=subprocess.PIPE)
	# uploading_sketch.wait()

time.sleep(.5)
def serial_connect():
	device_list = find_device()
	waiting_for_serial = True
	print('Trying to connect to {} on port {}'.format(device_list[0]['board_name'], device_list[0]['board_port']))
	time.sleep(3)
	while waiting_for_serial:
		try:
			print("trying to connect to serial")
			serial_port_handler = serial.Serial(device_list[0]['board_port'], 9600, write_timeout = 5)
			waiting_for_serial = False

		except:
			print("cannot connect to serial")
			waiting_for_serial = True
		time.sleep(0.1)
	return serial_port_handler

def serial_disconnect():
	serial_port.close()


serial_port = serial_connect()
time.sleep(2)
sketch_unknown = True
while(sketch_unknown):
	if(get_sketch_info() != (ERROR.SKETCH_UNKNOWN)):
		print("Correct Sketch Installed")
		sketch_unknown = False
		break
	print("Wrong Sketch Installed. Installation in progress...")
	serial_disconnect()
	time.sleep(1)
	install_sketch()
	time.sleep(1)
	serial_port = serial_connect()
	time.sleep(3)

time.sleep(1)
if only_serial:
	device_id = device_name
# send GET_CSR command (has payload > 0)
# pass in the device_name as payload
# ******* CHANGE TO THE DEVICE ID RETURNED BY THE API *********
print("REQUEST CSR")
print(f"Device ID: {device_id}")
msg_payload = []
msg_payload.append(COMMAND.GET_CSR.value)

msg_payload += list(bytearray(device_id.encode()))
serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
time.sleep(3)

response_data = []

while(serial_port.in_waiting > 0):
	response_data.append(int.from_bytes(serial_port.read(), "little"))

print(response_data)
csr = ""
parsed_response = parse_response_data(response_data, ERROR.CRC_FAIL)
if(parsed_response != ERROR.CRC_FAIL):
	print("CSR received")
	csr = bytearray(parsed_response).decode('utf-8')
	print(csr)
#	certificate = send_csr(token, csr, device_id)
else:
	print("CSR data corrupted")
	print("Please relaunch the script to retry")
	

# board will generate CSR
# wait for CSR or NACK


certificate = send_csr(token, csr, device_id)
print(certificate)


# BEGIN STORAGE PROCESS ON DEVICE
msg_payload = []
msg_payload.append(COMMAND.BEGIN_STORAGE.value)

serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
time.sleep(1)
response_data = []
while(serial_port.in_waiting > 0):
	response_data.append(int.from_bytes(serial_port.read(), "little"))

print(response_data)
parsed_response = parse_response_data(response_data, ERROR.GENERIC)
print(f"begin storage response: {parsed_response}")
if(parsed_response != ERROR.CRC_FAIL):
	print("ACK: Crypto Storage INIT OK")
#	certificate = send_csr(token, csr, device_id)
else:
	print("data corrupted")
	print("Please relaunch the script to retry")


year = certificate['not_before'][:4]
print(year)
send_command(COMMAND.SET_YEAR.value, year, True, "YEAR set")

month = certificate['not_before'][5:7]
print(month)
send_command(COMMAND.SET_MONTH.value, month, True, "MONTH set")

day = certificate['not_before'][8:10]
print(day)
send_command(COMMAND.SET_DAY.value, day, True, "DAY set")

hour = certificate['not_before'][11:13]
print(hour)
send_command(COMMAND.SET_HOUR.value, hour, True, "HOUR set")

years_validity = "31"
print("Validity in years")
print(years_validity)
send_command(COMMAND.SET_VALIDITY.value, years_validity, True, "VALIDITY set")

cert_serial = bytearray.fromhex(certificate['serial'])
print("Cert Serial")
print(cert_serial)
send_command(COMMAND.SET_CERT_SERIAL.value, cert_serial, False, "Serial set")

cert_authority_key_id = bytearray.fromhex(certificate['authority_key_identifier'])
print("Cert Auth Key ID")
print(cert_authority_key_id)
send_command(COMMAND.SET_AUTH_KEY.value, cert_authority_key_id, False, "Authority Key ID set")

signature = bytearray.fromhex(certificate['signature_asn1_x'] + certificate['signature_asn1_y'])
print("asn1_x")
print(certificate['signature_asn1_x'])
print("asn1_y")
print(certificate['signature_asn1_y'])
print("Cert Combined Signature")
print(signature)
send_command(COMMAND.SET_SIGNATURE.value, signature, False, "Signature set")

send_command(COMMAND.END_STORAGE.value, {0})

# msg_payload = []
# msg_payload.append(COMMAND.SET_YEAR.value)

# msg_payload += list(bytearray(year.encode()))
# print(f"year encoded: {bytearray(year.encode())}")
# serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
# time.sleep(1)
# response_data = []

# while(serial_port.in_waiting > 0):
# 	response_data.append(int.from_bytes(serial_port.read(), "little"))

# print(response_data)

# parsed_response = parse_response_data(response_data, ERROR.ERROR_GENERIC)
# print(f"set_year response: {parsed_response}")
# if(parsed_response != ERROR.CRC_FAIL):
# 	print("ACK: year correctly stored")
# #	certificate = send_csr(token, csr, device_id)
# else:
# 	print("data corrupted")
# 	print("Please relaunch the script to retry")
	



# month = certificate['not_before'][5:7]
# print(month)
# msg_payload = []
# msg_payload.append(COMMAND.SET_MONTH.value)

# msg_payload += list(bytearray(month.encode()))

# serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
# time.sleep(1)
# response_data = []

# while(serial_port.in_waiting > 0):
# 	response_data.append(int.from_bytes(serial_port.read(), "little"))

# print(response_data)

# parsed_response = parse_response_data(response_data, ERROR.ERROR_GENERIC)
# print(f"set_month response: {parsed_response}")
# if(parsed_response != ERROR.CRC_FAIL):
# 	print("ACK: month correctly stored")
# #	certificate = send_csr(token, csr, device_id)
# else:
# 	print("data corrupted")
# 	print("Please relaunch the script to retry")




# day = int(certificate['not_before'][8:10])
# print(day)
# hour = int(certificate['not_before'][11:13])
# print(hour)
# years_validity = 31
# print(years_validity)
# cert_serial = certificate['serial'].encode()
# print(cert_serial)
# cert_authority_key_id = (certificate['authority_key_identifier']).encode()
# print(cert_authority_key_id)
# signature = (certificate['signature_asn1_x'] + certificate['signature_asn1_y']).encode()
# print(signature)




# if not only_serial:
# 	readme = serial_port.readline()
# 	#print(readme[:-2].decode())
# 	if readme[:-2].decode() == 'Would you like to generate a new private key and CSR (y/N): ':
# 		print('Would you like to generate a new private key and CSR (y/N): y')
# 		time.sleep(0.2)
# 		serial_port.write('y\n'.encode())
# 	if readme[:-2].decode() == 'Please enter the device id: ':
# 		print('Please enter the device id: {}'.format(device_id))
# 		time.sleep(0.2)
# 		serial_port.write((device_id + '\n').encode())
# 	if readme[:5].decode() == '-----':
# 		i = 0
# 		csr = ''
# 		while i < 7:
# 			if i != 6:
# 				csr = csr + readme.decode()
# 				readme = serial_port.readline()
# 			else:
# 				csr = csr + readme[:-1].decode()
# 			i+= 1
# 		print(csr)
# 		certificate = send_csr(token, csr, device_id)
# 	if readme[:-2].decode() == 'Please enter the issue year of the certificate (2000 - 2031): ':
# 		year = str(int(certificate['not_before'][:4]))
# 		print('Please enter the issue year of the certificate (2000 - 2031): {}'.format(year))
# 		time.sleep(0.2)
# 		serial_port.write((year + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter the issue month of the certificate (1 - 12): ':
# 		month = str(int(certificate['not_before'][5:7]))
# 		print('Please enter the issue month of the certificate (1 - 12): {}'.format(month))
# 		time.sleep(0.2)
# 		serial_port.write((month + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter the issue day of the certificate (1 - 31): ':
# 		day = str(int(certificate['not_before'][8:10]))
# 		print('Please enter the issue day of the certificate (1 - 31): {}'.format(day))
# 		time.sleep(0.2)
# 		serial_port.write((day + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter the issue hour of the certificate (0 - 23): ':
# 		hour = str(int(certificate['not_before'][11:13]))
# 		print('Please enter the issue hour of the certificate (0 - 23): {}'.format(hour))
# 		time.sleep(0.2)
# 		serial_port.write((hour + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter how many years the certificate is valid for (0 - 31): ':
# 		print('Please enter how many years the certificate is valid for (0 - 31): 31')
# 		time.sleep(0.2)
# 		serial_port.write(('31\n').encode())
# 	if readme[:-2].decode() == 'Please enter the certificates serial number: ':
# 		print('Please enter the certificates serial number: {}'.format(certificate['serial']))
# 		time.sleep(0.2)
# 		serial_port.write((certificate['serial'] + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter the certificates authority key identifier: ':
# 		print('Please enter the certificates authority key identifier: {}'.format(certificate['authority_key_identifier']))
# 		time.sleep(0.2)
# 		serial_port.write((certificate['authority_key_identifier'] + '\n').encode())
# 	if readme[:-2].decode() == 'Please enter the certificates signature: ':
# 		signature = str(certificate['signature_asn1_x'] + certificate['signature_asn1_y'])
# 		print('Please enter the certificates signature: {}'.format(signature))
# 		time.sleep(0.2)
# 		serial_port.write((signature + '\n').encode())
# 		time.sleep(2)
# 		#break
# 	time.sleep(0.1)

print('Done! New device {} added.'.format(device_name))



