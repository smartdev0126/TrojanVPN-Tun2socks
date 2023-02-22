import NetworkExtension
import ProxyConfig

class PacketTunnelProvider: NEPacketTunnelProvider {
    var proxyClient: TrojanProxy!
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let tunnelNetworkSettings = createTunnelSettings()
        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            let tunFd = self?.packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
            switch ProxyConfig.preferHandler {
            case .Socks5:
                let host = ProxyConfig.getStringConfig(name: ProxyConfig.ConfigKey.Host.rawValue)!
                let port = ProxyConfig.getIntConfig(name: ProxyConfig.ConfigKey.Port.rawValue)!
                let password = ProxyConfig.getStringConfig(name: ProxyConfig.ConfigKey.Password.rawValue)!
                let proxyServer = "127.0.0.1:1080"
                
                self?.proxyClient = TrojanProxy(local_host: "127.0.0.1", local_port: 1080, remote_host: host, remote_port: UInt16(port), password: password)
                self?.proxyClient.start()
                NSLog("proxy server \(proxyServer)")
                DispatchQueue.global(qos: .default).async {
                    run(tunFd, "socks", proxyServer, "", "")
                }
                break
            }
            NSLog("tunnel start")
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("tunnel stop")
        completionHandler()
        if (proxyClient != nil) {
            proxyClient.stop()
        }
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Add code here to handle the message.
        if let handler = completionHandler {
            handler(messageData)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        // Add code here to get ready to sleep.
        completionHandler()
    }
    
    override func wake() {
        // Add code here to wake up.
    }
    
    func createTunnelSettings() -> NEPacketTunnelNetworkSettings  {
        let newSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "240.0.0.10")
        newSettings.ipv4Settings = NEIPv4Settings(addresses: ["240.0.0.1"], subnetMasks: ["255.255.255.0"])
        newSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.`default`()]
        // newSettings.ipv6Settings?.includedRoutes = [NEIPv6Route.`default`()]
        newSettings.proxySettings = nil
        newSettings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        newSettings.mtu = 1500
        return newSettings
    }
}
