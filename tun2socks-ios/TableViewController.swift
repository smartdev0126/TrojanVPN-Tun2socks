import UIKit
import NetworkExtension
import ProxyConfig

class TableViewController: UITableViewController {
    
    var manager = VPNManager.shared()

    @IBOutlet weak var statusLabel: UILabel!
    
    @IBOutlet weak var connectBtn: UIButton!
    
    @IBOutlet weak var hostField: UITextField!
    @IBOutlet weak var portField: UITextField!
    @IBOutlet weak var passwordField : UITextField!
    
    @IBAction func onClickConnectBtn(_ sender: Any) {
        updateConfig()
        manager.enableVPNManager() { error in
            guard error == nil else {
                fatalError("enable VPN failed: \(error.debugDescription)")
            }
            self.manager.toggleVPNConnection() { error in
                guard error == nil else {
                    fatalError("toggle VPN connection failed: \(error.debugDescription)")
                }
            }
        }
    }
    
    @objc func updateStatus() {
        connectBtn.setTitle(manager.manager.connection.status == .connected ? "Disconnect" : "Connect", for: .normal)
        statusLabel.text = manager.manager.connection.status.description
    }
    
    func updateConfig() {
        ProxyConfig.storeStringConfig(name: ProxyConfig.ConfigKey.Host.rawValue, value: hostField.text!)
        ProxyConfig.storeIntConfig(name: ProxyConfig.ConfigKey.Port.rawValue, value: Int(portField.text!)!)
        ProxyConfig.storeStringConfig(name: ProxyConfig.ConfigKey.Password.rawValue, value: passwordField.text!)
    }
    
    func updateUI() {
        hostField.text = ProxyConfig.getStringConfig(name: ProxyConfig.ConfigKey.Host.rawValue)
        portField.text = String(ProxyConfig.getIntConfig(name: ProxyConfig.ConfigKey.Port.rawValue)!)
        passwordField.text = String(ProxyConfig.getStringConfig(name: ProxyConfig.ConfigKey.Password.rawValue)!)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        manager.loadVPNPreference() { error in
            guard error == nil else {
                fatalError("load VPN preference failed: \(error.debugDescription)")
            }
            self.updateStatus()
            NotificationCenter.default.addObserver(self, selector: #selector(self.updateStatus), name: NSNotification.Name.NEVPNStatusDidChange, object: self.manager.manager.connection)
        }
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        updateUI()
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self, name: NSNotification.Name.NEVPNStatusDidChange, object: self.manager.manager.connection)
    }
}
