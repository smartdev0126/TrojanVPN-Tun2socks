import Foundation
import CocoaAsyncSocket
import CommonCrypto
import Network
import CryptoSwift

public class SOCKS5Address {
    enum AddressType: Int {
        case IPV4 = 1
        case DOMAINNAME = 3
        case IPV6 = 4
    }
    var addressType: AddressType!
    var address: String!
    var port: UInt16!
    public func parse(data: Data) -> Int {
        let firstVal = Array(data[data.startIndex..<data.index(data.startIndex, offsetBy: 1)])[0]
        let adrType = AddressType(rawValue: Int(firstVal))
        if (data.count == 0 || (adrType != AddressType.IPV4 && adrType != AddressType.DOMAINNAME && adrType != AddressType.IPV6)) {
            return -1
        }
        addressType = adrType
        switch addressType! {
        case AddressType.IPV4:
            if (data.count > 4 + 2) {
                let ad: [UInt8] = Array(data)
                address = "\(ad[1] ).\(ad[2]).\(ad[3]).\(ad[4])"
                port = UInt16(ad[5] << 8 + ad[6])
                return 1 + 4 + 2
            }
            break
        case AddressType.DOMAINNAME:
            let ad: [UInt8] = Array(data)
            let domain_len = Int(ad[1])
            if (domain_len == 0) {
                return -1
            }
            if (data.count > 1 + domain_len + 2) {
                address = String(decoding: data[data.index(data.startIndex, offsetBy: 2)..<data.index(data.startIndex, offsetBy: 2 + domain_len)], as: UTF8.self)
                print(ad[2 + domain_len])
                print(UInt16(ad[2 + domain_len]) << 8)
                port = UInt16(ad[2 + domain_len]) << 8 + UInt16(ad[3 + domain_len])
                return 1 + 1 + domain_len + 2
            }
            break
        case AddressType.IPV6:
            if (data.count > 16 + 2) {
                let ad: [UInt8] = Array(data)
                address = String(format: "%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx", ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7], ad[8], ad[9], ad[10], ad[11], ad[12], ad[13], ad[14], ad[15], ad[16])
                port = UInt16(ad[17] << 8 + ad[18])
                return 16 + 2
            }
            break
        }
        return -1
    }
    
    public func generate(address: String, port: UInt16) -> Data {
        var result:Data
        if (address.count > 15) {
            // ipv6 address
            let ad = withUnsafeBytes(of: IPv6Address(address)?.rawValue) {
                $0
            }
            result = Data(bytes: [4, ad[0], ad[1], ad[2], ad[3], ad[4], ad[5], ad[6], ad[7], ad[8], ad[9], ad[10], ad[11], ad[12], ad[13], ad[14], ad[15], port >> 8, port & 0xFF], count: 19)
        }
        else {
            // ipv4 address
            let ad = withUnsafeBytes(of: IPv4Address(address)?.rawValue) {
                $0
            }
            result = Data(bytes: [1, ad[0], ad[1], ad[2], ad[3], port >> 8, port & 0xFF], count: 7)
        }
        return result
    }
}

public class TrojanRequest {
    public var command: Int!
    public var address: SOCKS5Address!
    public var payload: String!
    public var password: String!
    
    enum COMMAND: Int {
    case CONNECT = 1
    case UDP_ASSOCIATE = 3
    }
    
    public func parse(data: String) -> Int {
        let index = data.range(of: "\r\n")
        if (index == nil) {
            return -1
        }
        let pos = data.distance(from: data.startIndex, to: index!.lowerBound)
        password = String(data[data.startIndex..<data.index(data.startIndex, offsetBy: pos)])
        let payload = String(data[data.index(data.startIndex, offsetBy: pos + 2)..<data.endIndex])
        let cmd = Array(payload[payload.startIndex..<payload.index(payload.startIndex, offsetBy: 1)])[0].asciiValue!
        if (payload.count == 0 || (cmd != COMMAND.CONNECT.rawValue && cmd != COMMAND.UDP_ASSOCIATE.rawValue)) {
            return -1
        }
        command = Int(cmd)
        address = SOCKS5Address()
        let address_len = address.parse(data: Data(payload[payload.index(payload.startIndex, offsetBy: 1)..<payload.endIndex].utf8))
        let last_part = String(payload[payload.index(payload.startIndex, offsetBy: address_len + 1)..<payload.index(payload.startIndex, offsetBy: address_len + 3)])
        if (address_len == -1 || (address_len + 3 < payload.count) || last_part != "\r\n") {
            return -1
        }
        self.payload = String(payload[payload.index(payload.startIndex, offsetBy:address_len + 3)..<payload.endIndex])
        return data.count
    }
    
    public func generate(password: String, domainName: String, port: UInt16, tcp: Bool) -> Data {
        var ret = (password + "\r\n").data(using: .utf8)
        if (tcp) {
            ret!.append(1)
        }
        else {
            ret!.append(3)
        }
        ret!.append(3)
        ret!.append(UInt8(domainName.count))
        ret!.append(domainName.data(using: .utf8)!)
        ret!.append(UInt8(port >> 8))
        ret!.append(UInt8(port & 0xFF))
        ret!.append("\r\n".data(using: .utf8)!)
        return ret!
    }
}

public class TrojanSession:NSObject, GCDAsyncSocketDelegate, GCDAsyncUdpSocketDelegate {
    public var out_socket: GCDAsyncSocket!
    public var in_socket: GCDAsyncSocket!
    public var udp_socket: GCDAsyncUdpSocket!
    
    public var remote_host: String
    public var remote_port: UInt16
    public var queue:DispatchQueue!
    public var out_write_buf: Data
    public var server_connected: Bool
    public var password: String!
    public var is_udp: Bool = false
    public var udp_recv_address: Data!
    public var udp_data_buf = Data([])
    
    enum STATUS: Int {
        case HANDSHAKE = 0
        case REQUEST = 1
        case CONNECT = 2
        case FORWARD = 3
        case UDP_FORWARD = 4
    }
    public init(socket: GCDAsyncSocket, remote_host: String, remote_port: UInt16, password: String) {
        self.in_socket = socket
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.server_connected = false
        self.out_write_buf = Data()
        self.password = password
        queue = DispatchQueue(label: "delegate queue")
        super.init()
    }
    
    public func start() {
        self.in_socket.setDelegate(self, delegateQueue: queue)
        self.in_socket.readData(withTimeout: -1, tag: STATUS.HANDSHAKE.rawValue)
    }
    
    public func socket(_ sock: GCDAsyncSocket, didConnectToHost host: String, port: UInt16) {
        #if TARGET_OS_IPHONE
        sock.perform {
            sock.enableBackgroundingOnSocket = false
        }
        #endif
        sock.startTLS(nil)
    }
    
    public func socketDidSecure(_ sock: GCDAsyncSocket) {
        server_connected = true
        out_socket.readData(withTimeout: -1, tag: STATUS.FORWARD.rawValue)
        out_socket.write(out_write_buf, withTimeout: -1, tag: STATUS.FORWARD.rawValue)
    }
    
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let bytes: [UInt8] = Array(data)
        if (tag == STATUS.HANDSHAKE.rawValue) {
            if (bytes[0] != 5) {
                return
            }
            var has_method = false
            let method_cnt = bytes[1]
            for index in 2..<(method_cnt + 2) {
                if (bytes[Int(index)] == 0) {
                    has_method = true
                    break
                }
            }
            if (!has_method) {
                return
            }
            else {
                in_socket.write(Data([5, 0]), withTimeout: -1, tag: STATUS.REQUEST.rawValue)
                in_socket.readData(withTimeout: -1, tag: STATUS.REQUEST.rawValue)
            }
        }
        if (tag == STATUS.REQUEST.rawValue) {
            if (bytes.count == 0 || bytes[0] != 5 || bytes[2] != 0) {
                return
            }
            
            var send_data = password.sha224().data(using: .utf8)
            send_data!.append("\r\n".data(using: .utf8)!)
            send_data?.append(bytes[1])
            send_data?.append(Data(data[data.index(data.startIndex, offsetBy: 3)..<data.endIndex]))
            send_data?.append("\r\n".data(using: .utf8)!)
            
            out_write_buf = send_data!
            
            is_udp = (bytes[1] == TrojanRequest.COMMAND.UDP_ASSOCIATE.rawValue)
            if (is_udp) {
                udp_socket = GCDAsyncUdpSocket.init(delegate: self, delegateQueue: queue)
                do {
                    try udp_socket.bind(toPort: in_socket.connectedPort)
                }
                catch {
                    
                }
                let address = SOCKS5Address()
                in_socket.write(Data([5, 0, 0]) + address.generate(address: in_socket.connectedHost!, port: in_socket.connectedPort), withTimeout: -1, tag: STATUS.CONNECT.rawValue)
            }
            else {
                in_socket.write(Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]), withTimeout: -1, tag: STATUS.CONNECT.rawValue)
            }
        }
        if (tag == STATUS.CONNECT.rawValue && server_connected == false) {
            out_write_buf += data
        }
        if (tag == STATUS.FORWARD.rawValue || server_connected == true) {
            if (sock == in_socket) {
                out_socket.write(data, withTimeout: -1, tag: STATUS.FORWARD.rawValue)
            }
            else {
                in_socket.write(data, withTimeout: -1, tag: STATUS.FORWARD.rawValue)
            }
        }
        if (tag == STATUS.UDP_FORWARD.rawValue) {
            udp_socket.send(data, withTimeout: -1, tag: STATUS.UDP_FORWARD.rawValue)
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        if (tag == STATUS.CONNECT.rawValue) {
            in_socket.readData(withTimeout: -1, tag: STATUS.CONNECT.rawValue)
            if (is_udp) {
                do {
                    try udp_socket.beginReceiving()
                }
                catch {
                    
                }
            }
            connectToServer()
        }
        if (tag == STATUS.FORWARD.rawValue) {
            if (sock == in_socket) {
                out_socket.readData(withTimeout: -1, tag: STATUS.FORWARD.rawValue)
            }
            else {
                in_socket.readData(withTimeout: -1, tag: STATUS.FORWARD.rawValue)
            }
        }
    }
    
    public func udpSocket(_ sock: GCDAsyncUdpSocket, didReceive data: Data, fromAddress address: Data, withFilterContext filterContext: Any?) {
        udp_recv_address = address
        if (data.count == 0) {
            return
        }
        let bytes: [UInt8] = Array(data)
        if (data.count < 3 || (bytes[0] != 0) || bytes[1] != 0 || bytes[2] != 0) {
            return
        }
        let address = SOCKS5Address()
        let address_len = address.parse(data: Data(data[data.index(data.startIndex, offsetBy: 3)..<data.endIndex]))
        
        if (address_len == -1) {
            return
        }
        
        var send_data = Data(data[data.index(data.startIndex, offsetBy: 3)..<data.index(data.startIndex, offsetBy: 3 + address_len)])
        send_data.append(UInt8(address_len >> 8))
        send_data.append(UInt8(address_len & 0xFF))
        send_data.append("\r\n".data(using: .utf8)!)
        send_data.append(Data(data[data.index(data.startIndex, offsetBy: 3 + address_len)..<data.endIndex]))
        if (server_connected) {
            out_socket.write(send_data, withTimeout: -1, tag: STATUS.UDP_FORWARD.rawValue)
        }
        else {
            out_write_buf += send_data
        }
    }
    
    public func udpSocket(_ sock: GCDAsyncUdpSocket, didSendDataWithTag tag: Int) {
        if (udp_data_buf.count == 0) {
            return
        }
        let address = SOCKS5Address()
        let address_len = address.parse(data: udp_data_buf)
        let bytes: [UInt8] = Array(udp_data_buf)
        if (address_len == -1 || udp_data_buf.count < address_len + 2) {
            return
        }
        let length = Int((bytes[address_len] << 8) + (bytes[address_len + 1] & 0xFF))
        if (udp_data_buf.count < address_len + 4 + length || String(decoding: Data(udp_data_buf[udp_data_buf.index(udp_data_buf.startIndex, offsetBy: address_len + 2)..<udp_data_buf.index(udp_data_buf.startIndex, offsetBy: address_len + 4)]), as: UTF8.self) != "\r\n") {
            return
        }
        let payload = Data(udp_data_buf[udp_data_buf.index(udp_data_buf.startIndex, offsetBy: address_len + 4)..<udp_data_buf.index(udp_data_buf.startIndex, offsetBy: address_len + length + 4)])
        let udp_packet_len = 4 + address_len + length
        let reply = Data([5, 0, 0]) + Data(udp_data_buf[udp_data_buf.startIndex..<udp_data_buf.index(udp_data_buf.startIndex, offsetBy: address_len)]) + payload
        udp_data_buf = Data(udp_data_buf[udp_data_buf.index(udp_data_buf.startIndex, offsetBy: udp_packet_len)..<udp_data_buf.endIndex])
        udp_socket.send(reply, toAddress: udp_recv_address, withTimeout: -1, tag: STATUS.UDP_FORWARD.rawValue)
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
    }
    
    public func connectToServer() {
        self.out_socket = GCDAsyncSocket(delegate: self, delegateQueue: DispatchQueue(label: "delegate out queue"))
        do {
            try self.out_socket.connect(toHost: remote_host, onPort: remote_port, withTimeout: -1)
        }
        catch let error{
            print("Connect to host \(error)")
        }
    }
    public func destroy() {
        if (self.in_socket.isConnected) {
            self.in_socket.disconnect()
        }
        if (self.out_socket.isConnected) {
            self.out_socket.disconnect()
        }
    }
}

public class TrojanProxy: NSObject, GCDAsyncSocketDelegate {
    public var socket: GCDAsyncSocket!
    public var local_host: String
    public var local_port: UInt16
    public var remote_host: String
    public var remote_port: UInt16
    public var queue:DispatchQueue!
    public var sessions: [TrojanSession]
    public var connectedSocket: GCDAsyncSocket!
    public var password: String!
    public init(local_host: String, local_port: UInt16, remote_host: String, remote_port: UInt16, password: String) {
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.password = password
        sessions = []
        super.init()
    }
    public func start() {
        queue = DispatchQueue(label: "listen socket delegate queue")
        socket = GCDAsyncSocket.init(delegate: self, delegateQueue: queue)
        #if TARGET_OS_IPHONE
        socket.perform {
            socket.enableBackgroundingOnSocket = false
        }
        #endif
        do {
            try socket.accept(onInterface: local_host, port: local_port)
        }
        catch let error{
            print("listen error \(error)")
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
        #if TARGET_OS_IPHONE
        newSocket.perform {
            newSocket.enableBackgroundingOnSocket = false
        }
        #endif
        let session = TrojanSession(socket: newSocket, remote_host: self.remote_host, remote_port: self.remote_port, password: self.password)
            session.start()
        self.sessions.append(session)
    }
    
    public func stop() {
        socket.disconnect()
        for session in self.sessions {
            session.destroy()
        }
        self.sessions.removeAll()
    }
}
