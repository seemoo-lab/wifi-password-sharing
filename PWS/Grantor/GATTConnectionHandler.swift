import Foundation
import CoreBluetooth

// MARK: - GATTConnectionHandler

/// PWSGATTConnectionHandler
///
/// Searches for given Service and Characteristic and inits PWSHandler.
/// Also assembles recived data to WDNearbyFrames
///
class GATTConnectionHandler: NSObject {

    var shareInfo: PWSGrantorHandler.ShareInfo

    var handler: PWSGrantorHandler?

    // Long packages will be transmitted by spliting it into chuncks and writing each chunck one by one. We cache them here.
    var openFrame: WDNearbyFrame?

    fileprivate var serviceUUID: CBUUID
    fileprivate var characteristicUUID: CBUUID

    init(peripheral: CBPeripheral, shareInfo: PWSGrantorHandler.ShareInfo, serviceUUID: CBUUID, characteristicUUID: CBUUID) {
        self.shareInfo = shareInfo
        self.serviceUUID = serviceUUID
        self.characteristicUUID = characteristicUUID
        super.init()
        peripheral.delegate = self
        peripheral.discoverServices([serviceUUID])
    }

}

// MARK: - CBPeripheralDelegate

extension GATTConnectionHandler: CBPeripheralDelegate {

    // Gets called after peripheral services have been discoved
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        // Filter services for the PWSService and discover the PWSCharacteristic on it
        if let pwsServices = peripheral.services?.first(where: { $0.uuid == serviceUUID }) {
            peripheral.discoverCharacteristics([characteristicUUID], for: pwsServices)
        }
    }

    // Gets called after the characteristic have been discoverd, we init the pws handler here
    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        // Find the pws characteristic
        if let characteristic = service.characteristics?.first(where: {$0.uuid == characteristicUUID}) {
            if self.handler == nil {
                do {
                    self.handler = try PWSGrantorHandler(peripheral: peripheral, characteristic: characteristic, shareInfo: shareInfo)
                } catch let error {
                    print("ERROR: \(error)")
                }
            }
        }
    }

    // Callback after we wrote a value to a characteristic, we use it to inform the handler that he can send the next chunck of data
    public func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error = error {
            print("ERROR didWriteValueFor: \(characteristic.uuid) \(error)")
        } else {
            handler?.didWriteValue()
        }
    }

    // Main recived data function which gets the raw value which gets written to the pws characteristic
    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let data = characteristic.value {
            // If we have a open frame (a frame with missing bytes) we just append the recived data completly
            if let openFrame = self.openFrame {
                openFrame.appendData(data: data.bytes)
            }
            // If there is no open frame, we init a new one
            else {
                // The recived data needs 2 byte for the length, another 2 for frame type and serivice type, plus the actual payload, so new frames have to be at least 5 bytes long
                if data.count >= 5 {
                    self.openFrame = try! WDNearbyFrame(data: data.bytes)
                } else {
                    print("ERROR: Received a frame to short")
                }
            }

            // After init a new frame or appending data to an open frame, we check if the frame is complete
            if self.openFrame?.isComplete == true {
                // If the frame is complete we call the recived frame handler
                if let frame = self.openFrame {
                    self.handler?.receivedFrame(frame)
                }

                // Reset open frame to be ready for the next
                self.openFrame = nil
            }
        }
    }

}

class PWSGATTConnectionHandler: GATTConnectionHandler {
    init(peripheral: CBPeripheral, shareInfo: PWSGrantorHandler.ShareInfo) {
        super.init(peripheral: peripheral, shareInfo: shareInfo, serviceUUID: PWSServiceUUID, characteristicUUID: PWSCharacteristicUUID)
    }
}
