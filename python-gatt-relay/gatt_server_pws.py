from __future__ import print_function
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service

import array
from hashlib import sha256

try:
    from gi.repository import GObject
except ImportError:
    import gobject as GObject
import advertising
import gatt_server
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a", "--adapter-name", type=str, help="Adapter name", default=""
    )
    parser.add_argument("-s", "--ssid", type=str, help="SSID")
    parser.add_argument(
        "-c", "--contact", type=str, help="Email address or phone number"
    )
    args = parser.parse_args()
    adapter_name = args.adapter_name

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    mainloop = GObject.MainLoop()

    # Define PWS BLE advertisement template
    data = [
        0x0F,
        0x11,
        # Action flags
        0xC0,
        # Action type
        0x08,
        # Authentication tag
        0x00,
        0x00,
        0x00,
        # Contact 1
        0x00,
        0x00,
        0x00,
        # Contact 2
        0x00,
        0x00,
        0x00,
        # Contact 2
        0x00,
        0x00,
        0x00,
        # SSID
        0x00,
        0x00,
        0x00,
    ]

    # Hash inputs
    ssid_hash = sha256(args.ssid.encode()).digest()
    contact_hash = sha256(args.contact.encode()).digest()

    # Fill advertisement template
    data[7:10] = contact_hash[:3]
    data[10:13] = contact_hash[:3]
    data[13:16] = contact_hash[:3]
    data[16:19] = ssid_hash[:3]

    advertising.advertising_main(mainloop, bus, adapter_name, data)
    gatt_server.gatt_server_main(mainloop, bus, adapter_name)
    mainloop.run()


if __name__ == "__main__":
    main()
