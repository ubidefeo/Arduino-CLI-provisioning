#!/usr/bin/python3

import requests
import getpass
import json
import serial.tools.list_ports
import serial
import time
import subprocess
import crcmod
import os

import argparse

from enum import Enum, auto
import os

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
	RECONSTRUCT_CERT = auto()

# ERRORS
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

	#print(f"data size >>> {len(msg_payload)}")
	payload_size_L = (payload_size.to_bytes(2, "big"))[1]
	payload_size_H = (payload_size.to_bytes(2, "big"))[0]
	#print(f"{hex(payload_size_H)} - {hex(payload_size_L)}")

	formed_message.append(payload_size_H)
	formed_message.append(payload_size_L)
	formed_message += bytearray(msg_payload)
	crc = _CRC_FUNC(bytearray(msg_payload))
	#print(hex(crc))
	formed_message.append(((crc >> 8) & 0xff))
	formed_message.append(crc & 0xff)
	formed_message += bytearray(msg_end)
	#print(f"msg payload: {msg_payload}")
	#print(f"formed message: {formed_message}")
	return formed_message


	
def parse_response_data(r_data, failure_error):
	if(len(r_data) < 1):
		return ERROR.GENERIC
	msg_type = r_data[2]
	msg_length = r_data[3] << 8 | r_data[4]
	#print(f"incoming data length: {msg_length}")
	payload_bytes = (r_data[5:][:msg_length - CRC16_SIZE])
	#print(payload_bytes)
	payload_computed_CRC = _CRC_FUNC(bytearray(payload_bytes))
	#print(f"computed CRC: {hex(payload_computed_CRC)}")
	payload_received_CRC = r_data[len(r_data) - 4] << 8 | r_data[len(r_data) - 3]	
	#print(f"received CRC: {hex(payload_received_CRC)}")
	if(payload_computed_CRC == payload_received_CRC):
		return payload_bytes;
	else:
		return failure_error

def send_command(command, payload = bytearray([]), encode = False, verbose_message = "My job here is done."):
	msg_payload = []
	msg_payload.append(command.value)

	if(encode):
		msg_payload += list(bytearray(payload.encode()))
	else:
		msg_payload += list(bytearray(payload))

	serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
	time.sleep(3)
	response_data = []

	while(serial_port.in_waiting > 0):
		response_data.append(int.from_bytes(serial_port.read(), "little"))

	#print(response_data)

	parsed_response = parse_response_data(response_data, ERROR.CRC_FAIL)
	#print(f"{command} response: {parsed_response}")
	if(parsed_response != ERROR.CRC_FAIL):
		print(f"ACK: {verbose_message}")
		return parsed_response
	#	certificate = send_csr(token, csr, device_id)
	else:
		print("data corrupted")
		print("Please relaunch the script to retry")
		return ERROR.CRC_FAIL


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
	return json.loads(response.text)['compressed']

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
	elif port.pid in [int('0x2145', 16), int('0x2145', 16)]:
		return {'board_port': port.device, 'board_name': port.product, 'type': 'nano_33_iot', 'fqbn': 'arduino:samd:nano_33_iot', 'serial_number': port.serial_number}
	else:
		return None

def find_device():
	device_list = []
	i = 0
	while len(device_list) != 1:
		for port in serial.tools.list_ports.comports():
			if port.vid == 9025 or port.vid == 0x03eb:
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

def get_sketch_info():
	print('Querying Crypto Provisioning Sketch...')
	#print('Waiting for response...')
	msg_payload = []
	msg_payload.append(COMMAND.GET_SKETCH_INFO.value)
	#print(msg_payload)
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

def serial_connect():
	device_list = find_device()
	waiting_for_serial = True
	time.sleep(3)
	while waiting_for_serial:
		try:
			print(f"Attempting connection to {device_list[0]['board_name']} on port {device_list[0]['board_port']}")
			serial_port_handler = serial.Serial(device_list[0]['board_port'], 57600, write_timeout = 5)
			waiting_for_serial = False
		except:
			print("cannot connect to serial")
			waiting_for_serial = True
		time.sleep(2)
	return serial_port_handler

def serial_disconnect():
	serial_port.close()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Arduino IoT Cloud Provisioning Assistant')
	parser.add_argument('--api_credentials_file', help='Provide the file containing Client ID and API Secret. Example: --api_credentials_file=/home/myuser/apicredentials.json')
	parser.add_argument('--device_name', help='Choose the name your device will have in your dashboard. Example: --device_name=myNanoIoT')
	args = parser.parse_args()

if(args.api_credentials_file):
	json_config_file = args.api_credentials_file
else:
	home = os.path.expanduser('~')
	json_config_file = home + "/arduinoIoTCloudAPI.json"

try:
	with open(json_config_file) as json_cfg:
		api_credentials = json.load(json_cfg)
		client_id = api_credentials['client_id']
		secret_id = api_credentials['secret_id']
except Exception as e:
	print("*****  ERROR  *****")
	print(f"Failed to load Arduino IoT API Credentials JSON [{json_config_file}]")

if(args.device_name):
	device_name = args.device_name
else:
	device_name = f"IOTDevice_{int(time.time())}" #input('Device name: ')

print(f"Provisioning device with name {device_name}")

device_list = find_device()

token = generate_token(client_id, secret_id)
device_id = add_device(token, device_name, device_list[0]['fqbn'], device_list[0]['type'], device_list[0]['serial_number'])
print(f"IoT Cloud generated Device ID: {device_id}")

serial_port = serial_connect()
time.sleep(2)

sketch_unknown = True
while(sketch_unknown):
	if(get_sketch_info() != (ERROR.SKETCH_UNKNOWN)):
		print("Provisioning Sketch found. Moving forward...")
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

# send GET_CSR command (has payload > 0)
# pass in the device_name as payload
# ******* CHANGE TO THE DEVICE ID RETURNED BY THE API *********
print(f"REQUESTING CSR for Device with ID: {device_id}")
# msg_payload = []
# msg_payload.append(COMMAND.GET_CSR.value)
# msg_payload += list(bytearray(device_id.encode()))

# serial_port.write(compose_message(MESSAGE_TYPE.COMMAND.value, msg_payload))
# time.sleep(3)

# response_data = []

# while(serial_port.in_waiting > 0):
# 	response_data.append(int.from_bytes(serial_port.read(), "little"))

# print(response_data)
# csr = ""
# parsed_response = parse_response_data(response_data, ERROR.CRC_FAIL)
# if(parsed_response != ERROR.CRC_FAIL):
# 	print("CSR received")
# 	csr = bytearray(parsed_response).decode('utf-8')
# 	print(csr)
# #	certificate = send_csr(token, csr, device_id)
# else:
# 	print("CSR data corrupted")
# 	print("Please relaunch the script to retry")
	
print(device_id)
print(device_id.encode())
print(bytearray(device_id.encode()))
print(list(bytearray(device_id.encode())))

csr = send_command(command = COMMAND.GET_CSR, payload = list(bytearray(device_id.encode())), encode = False, verbose_message = "CSR Obtained")
if(csr != ERROR.CRC_FAIL):
	print("CSR received")
	csr = bytearray(csr).decode('utf-8')
else:
	print("CSR REQUEST FAILED. Data returned below:")
	print(csr)
	exit()

certificate = send_csr(token, csr, device_id)
print(certificate)

print("Requesting Begin Storage")
send_command(command = COMMAND.BEGIN_STORAGE, verbose_message = "Crytpo Storage INIT OK")

year = certificate['not_before'][:4]
print(f"Sending Year: {year}")
send_command(COMMAND.SET_YEAR, year, True, "YEAR set")

month = certificate['not_before'][5:7]
print(f"Sending Month: {month}")
send_command(COMMAND.SET_MONTH, month, True, "MONTH set")

day = certificate['not_before'][8:10]
print(f"Sending Day: {day}")
send_command(COMMAND.SET_DAY, day, True, "DAY set")

hour = certificate['not_before'][11:13]
print(f"Sending Hour: {hour}")
send_command(COMMAND.SET_HOUR, hour, True, "HOUR set")

years_validity = "31"
print(f"Sending Validity (years): {years_validity}")
send_command(COMMAND.SET_VALIDITY, years_validity, True, "VALIDITY set")

cert_serial = bytearray.fromhex(certificate['serial'])
print(f"Sending Certificate Serial: {cert_serial}")
send_command(COMMAND.SET_CERT_SERIAL, cert_serial, False, "Serial set")

cert_authority_key_id = bytearray.fromhex(certificate['authority_key_identifier'])
print(f"Sending Certificate Authority Key: {cert_authority_key_id}")
send_command(COMMAND.SET_AUTH_KEY, cert_authority_key_id, False, "Authority Key ID set")

signature = bytearray.fromhex(certificate['signature_asn1_x'] + certificate['signature_asn1_y'])
print(f"Sending Signature: {signature}")
send_command(COMMAND.SET_SIGNATURE, signature, False, "Signature set")
time.sleep(1)
print("Requesting End Storage")
send_command(COMMAND.END_STORAGE)

time.sleep(2)
print("Requesting Certificate Reconstruction")
send_command(command = COMMAND.RECONSTRUCT_CERT, verbose_message = "reconstruct ok")


print('Done! New device {} added.'.format(device_name))



