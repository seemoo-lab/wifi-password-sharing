from __future__ import print_function
import dbus
import dbus.exceptions
import dbus.mainloop.glib
import dbus.service

import binascii as bii
import array

import functools

try:
    from gi.repository import GObject
except ImportError:
    import gobject as GObject

from random import randint

import exceptions
import adapters

BLUEZ_SERVICE_NAME = "org.bluez"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

GATT_MANAGER_IFACE = "org.bluez.GattManager1"

GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
GATT_DESC_IFACE = "org.bluez.GattDescriptor1"


class Application(dbus.service.Object):
    """
    org.bluez.GattApplication1 interface implementation
    """

    def __init__(self, bus):
        self.path = "/"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)
        self.add_service(PWSService(bus, 0))

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        print("GetManagedObjects")

        for service in self.services:
            response[service.get_path()] = service.get_properties()
            chrcs = service.get_characteristics()
            for chrc in chrcs:
                response[chrc.get_path()] = chrc.get_properties()
                descs = chrc.get_descriptors()
                for desc in descs:
                    response[desc.get_path()] = desc.get_properties()

        return response


class Service(dbus.service.Object):
    """
    org.bluez.GattService1 interface implementation
    """

    PATH_BASE = "/org/bluez/example/service"

    def __init__(self, bus, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                "UUID": self.uuid,
                "Primary": self.primary,
                "Characteristics": dbus.Array(
                    self.get_characteristic_paths(), signature="o"
                ),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_characteristic_paths(self):
        result = []
        for chrc in self.characteristics:
            result.append(chrc.get_path())
        return result

    def get_characteristics(self):
        return self.characteristics

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_SERVICE_IFACE:
            raise exceptions.InvalidArgsException()

        return self.get_properties()[GATT_SERVICE_IFACE]


class Characteristic(dbus.service.Object):
    """
    org.bluez.GattCharacteristic1 interface implementation
    """

    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.descriptors = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_CHRC_IFACE: {
                "Service": self.service.get_path(),
                "UUID": self.uuid,
                "Flags": self.flags,
                "Descriptors": dbus.Array(self.get_descriptor_paths(), signature="o"),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    def get_descriptor_paths(self):
        result = []
        for desc in self.descriptors:
            result.append(desc.get_path())
        return result

    def get_descriptors(self):
        return self.descriptors

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_CHRC_IFACE:
            raise exceptions.InvalidArgsException()

        return self.get_properties()[GATT_CHRC_IFACE]

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        print("Default ReadValue called, returning error")
        raise exceptions.NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        print("Default WriteValue called, returning error")
        raise exceptions.NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StartNotify(self):
        print("Default StartNotify called, returning error")
        raise exceptions.NotSupportedException()

    @dbus.service.method(GATT_CHRC_IFACE)
    def StopNotify(self):
        print("Default StopNotify called, returning error")
        raise exceptions.NotSupportedException()

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class Descriptor(dbus.service.Object):
    """
    org.bluez.GattDescriptor1 interface implementation
    """

    def __init__(self, bus, index, uuid, flags, characteristic):
        self.path = characteristic.path + "/desc" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.flags = flags
        self.chrc = characteristic
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_DESC_IFACE: {
                "Characteristic": self.chrc.get_path(),
                "UUID": self.uuid,
                "Flags": self.flags,
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != GATT_DESC_IFACE:
            raise exceptions.InvalidArgsException()

        return self.get_properties()[GATT_DESC_IFACE]

    @dbus.service.method(GATT_DESC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        print("Default ReadValue called, returning error")
        raise exceptions.NotSupportedException()

    @dbus.service.method(GATT_DESC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        print("Default WriteValue called, returning error")
        raise exceptions.NotSupportedException()


class PWSService(Service):
    """
    PWS Service

    """

    PWS_SERVICE_UUID = "9FA480E0-4967-4542-9390-D343DC5D04AE"

    def __init__(self, bus, index):
        Service.__init__(self, bus, index, self.PWS_SERVICE_UUID, True)
        self.add_characteristic(PWSCharacteristic(bus, 0, self))


import socket


class PWSCharacteristic(Characteristic):
    """
    PWSCharacteristic

    """

    PWS_CHAR_UUID = "AF0BADB1-5B99-43CD-917A-A77BC549E3CC"
    ccc = None

    def __init__(self, bus, index, service):
        Characteristic.__init__(
            self, bus, index, self.PWS_CHAR_UUID, ["write", "notify"], service
        )
        self.notifying = False

        self.server("", 8080)

    def server(self, host, port):
        """Initialize server and start listening."""
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        print("Listening...")
        GObject.io_add_watch(sock, GObject.IO_IN, self.listener)

    def listener(self, sock, *args):
        """Asynchronous connection listener. Starts a handler for each connection."""
        conn, addr = sock.accept()
        self.ccc = conn
        print("Connected")
        GObject.io_add_watch(conn, GObject.IO_IN, self.handler)
        return True

    def handler(self, conn, *args):
        """Asynchronous connection handler. Processes each line from the socket."""
        line = conn.recv(4096)
        if not len(line):
            print("Connection closed.")
            return False
        else:
            self.write_using_notify(line)
            return True

    def WriteValue(self, value, options):
        data = bytearray(value)
        print("Received Data {}".format(bii.hexlify(data)))

        # Append length of the payload in the first byte
        data.insert(0, len(value))

        # Add padding to make the size 256 bytes total
        while len(data) < 256:
            data.append(0)
        self.ccc.send(data)

    value = None

    def ReadValue(self, options):
        print("Read Value")
        return self.value

    def write_using_notify(self, value):
        if not self.notifying:
            return
        value = [dbus.Byte(b) for b in value]
        print("Send Data: {}".format(bii.hexlify(bytearray(value))))
        self.value = value
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": value}, [])

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        print("Start Notify")

        self.notifying = True
        self.notify_battery_level()

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        print("Stop Notify")

        self.notifying = False


def register_app_cb():
    print("GATT application registered")


def register_app_error_cb(mainloop, error):
    print("Failed to register application: " + str(error))
    mainloop.quit()


def gatt_server_main(mainloop, bus, adapter_name):
    adapter = adapters.find_adapter(bus, GATT_MANAGER_IFACE, adapter_name)
    if not adapter:
        raise Exception("GattManager1 interface not found")

    service_manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter), GATT_MANAGER_IFACE
    )

    app = Application(bus)

    print("Registering GATT application...")

    service_manager.RegisterApplication(
        app.get_path(),
        {},
        reply_handler=register_app_cb,
        error_handler=functools.partial(register_app_error_cb, mainloop),
    )
