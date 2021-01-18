import Foundation
import CoreBluetooth

class PWSAdvertisementScanner {

    var connectionHandler: PWSGATTConnectionHandler?
    var activePeripheral: CBPeripheral?
    var scanner: BLEAdvertisementScanner?

    init(shareInfo: PWSGrantorHandler.ShareInfo) {
        scanner = BLEAdvertisementScanner { scanner in
            print("Scanning for PWS advertisments")
            scanner.startScanning { (advData, peripheral) in
                do {
                    if self.connectionHandler == nil {
                        guard let appleAdv = try AppleBLEAdvertisement(data: advData.bytes) else {
                            return
                        }

                        print(advData.hexadecimal)
                        if let pwsAdvertisement = shareInfo.checkAdvertisement(appleAdv, flags: flags) {
                            print("Start PWS with SSID hash: \(pwsAdvertisement.ssidHash.data.hexadecimal) and id: \(peripheral.identifier)")
                            scanner.stopScanning()
                            self.activePeripheral = peripheral
                            print("Try connecting to peripheral (\(peripheral.identifier))")
                            scanner.connect(peripheral) { (peripheral) in
                                print("Connected to peripheral (\(peripheral.identifier))")
                                self.connectionHandler = PWSGATTConnectionHandler(peripheral: peripheral, shareInfo: shareInfo)
                            }
                        }

                    }
                } catch let error {
                    print("Error \(error)")
                }
            }
        }
    }

}

/// BLEAdvertisementScanner
/// Scans for BLE advertisement and calls a given callback with the advertisement data on receive.
///
class BLEAdvertisementScanner: NSObject {
    typealias DidDiscoverPeripheralClosure = (Data, CBPeripheral) -> Void
    typealias DidConnectClosure = (CBPeripheral) -> Void

    private var centralManager: CBCentralManager!

    private var onScannerReady: ((BLEAdvertisementScanner) -> Void)?
    private var onDiscover: DidDiscoverPeripheralClosure?
    private var onConnected: DidConnectClosure?

    /// Init new BLEAdvertisementScanner
    ///
    /// @param onScannerReady       Callback which gets called once the scanner is ready to start scanning
    ///
    init(onScannerReady: @escaping (BLEAdvertisementScanner) -> Void) {
        self.onScannerReady = onScannerReady
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: DispatchQueue.main)
    }

    /// Start scanning for peripherals
    ///
    /// @param onDiscover       callback which gets called with received advertisment data
    ///
    func startScanning(_ onDiscover: @escaping DidDiscoverPeripheralClosure) {
        self.onDiscover = onDiscover
        startScanning()
    }

    /// Start scanning for peripherals
    func startScanning() {
        centralManager.scanForPeripherals(withServices: nil, options: nil)
    }

    /// Stop scanning for peripherals
    func stopScanning() {
        centralManager.stopScan()
    }

    /// Connect to given peripheral
    ///
    /// @param peripheral           CBPeripheral to connect to
    /// @param onConnected      Callback which gets called once the peripheral is connected
    ///
    func connect(_ peripheral: CBPeripheral, onConnected: @escaping DidConnectClosure) {
        self.onConnected = onConnected
        centralManager.connect(peripheral, options: [:])
    }
}

// MARK: - CBCentralManagerDelegate

extension BLEAdvertisementScanner: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            onScannerReady?(self)
            onScannerReady = nil
        case .poweredOff:
            central.stopScan()
        case .unsupported: fatalError("Unsupported BLE module")
        default: break
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        if let manufacturerData = advertisementData["kCBAdvDataManufacturerData"] as? Data {
            onDiscover?(manufacturerData, peripheral)
         }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        onConnected?(peripheral)
        onConnected = nil
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        print(error)
    }

}
