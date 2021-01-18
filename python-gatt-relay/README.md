# Python BLE GATT Server for Apple Wi-Fi Password Sharing

GATT is constructed out of one or more server devices (BLE peripherals) and a client device (BLE central).

A GATT server is usually a small device such as a sensor, but for some use cases you might want to have a Linux computer such as a Raspberry Pi used as a GATT server. This example is meant to demonstrate how this can be done.

## Setup

The instructions in this document were tested on a Raspberry Pi 4 running [Raspberry Pi OS (Raspian) Buster](https://www.raspberrypi.org/software/) with Linux kernel 5.4 and BlueZ 5.50.

## Install

Install dependencies:

```bash
sudo apt-get install python3-dbus python3-gi
```

## Usage

Start the BLE GATT server as root:

```bash
sudo -E python3 gatt_server_pws.py --ssid "<SSID>" --contact "<EMAIL_OR_PHONE>"
```

### Advertisement interval

To increase the chance that the advertisement is picked up by Apple devices, you can reduce the advertisement interval (value is multiplied by 0.625 ms):

```
echo 160 | sudo tee /sys/kernel/debug/bluetooth/hci0/adv_min_interval > /dev/null
echo 160 | sudo tee /sys/kernel/debug/bluetooth/hci0/adv_max_interval > /dev/null
```

## License

The code in this repository is based on code taken from the [BlueZ](http://www.bluez.org/) project. It is licensed under GPL 2.0
