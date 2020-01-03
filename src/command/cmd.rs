use super::*;
use heapless::{consts, String, Vec};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    // 3 General
    /// 3.1 AT Attention Command
    AT,
    /// 3.2 Manufacturer identification
    GetManufacturerId,
    /// 3.3 Model identification
    GetModelId,
    /// 3.4 Firmware version identification
    GetFWVersion,
    /// 3.5 Serial number
    GetSerialNum,
    /// Following commands are skipped, due to duplicates
    /// 3.6 Manufacturer identification (AT+GMI)
    /// 3.7 Model identification (AT+GMM)
    /// 3.8 Firmware version identification (AT+GMR)
    /// 3.10 Identification information I
    GetId,
    /// 3.11 Set greeting text\
    /// Set the greeting text\
    /// Configures and activates/deactivates the greeting text. The greeting text configuration's change will be
    /// applied at the subsequent boot. If active, the greeting text is shown at boot once, on any AT interface, if
    /// the module start up mode is set to command mode
    SetGreetingText {
        enable: bool,
        text: String<at::MaxCommandLen>,
    },
    /// Get the current greeting text
    GetGreetingText,

    // 4 System
    /// 4.1 Store current configuration
    Store,
    /// 4.2 Set to default configuration
    ResetDefault,
    /// 4.3 Set to factory defined configuration
    ResetFactory,
    /// 4.4 Circuit 108/2 (DTR) behavior
    SetDTR { value: DTRValue },
    /// 4.5 DSR Overide
    SetDSR { value: DSRValue },
    /// 4.6 ATE Echo On/Off\
    /// This command configures whether or not the unit echoes characters received from the DTE when in Command Mode.
    SetEcho { enable: bool },
    /// Read current echo setting
    GetEcho,
    /// 4.7 Escape Character\
    /// Configure the escape character used to switch the unit from data mode to Command Mode.
    /// Factory default: 43, i.e the '+' character
    SetEscape { esc_char: char },
    /// Read escape character
    GetEscape,
    /// 4.8 Command Line Termination Character\
    /// Write command line termination character\
    /// This setting changes the decimal value of the character recognized by the DCE from the DTE to terminate an
    /// incoming command line. It is also generated by the DCE as part of the header, trailer, and terminator for result
    /// codes and information text along with the S4 parameter.\
    /// The previous value of S3 is used to determine the command line termination character for entry of the command
    /// line containing the S3 setting command. However, the result code issued shall use the value of S3 as set during
    /// the processing of the command line. For example, if S3 was previously set to 13 and the command line
    /// "ATS3=30" is issued, the command line shall be terminated with a CR, character (13), but the result code issued
    /// will use the character with the ordinal value 30 in place of the CR
    SetTermination { line_term: char },
    /// Read command line termination character
    GetTermination,
    /// 4.9 Response Formatting Character\
    /// Write response formatting character\
    /// This setting changes the decimal value of the character generated by the DCE as part of the header, trailer, and
    /// terminator for result codes and information text, along with the S3 parameter.
    ///  If the value of S4 is changed in a command line, the result code issued in response to that command line will use the
    /// new value of S4
    SetFormatting { term: char },
    /// Read response formatting character
    GetFormatting,
    /// 4.10 Backspace Character\
    /// Write backspace character\
    /// This setting changes the decimal value of the character recognized by the DCE as a request to delete from the
    /// command line the immediately preceding character
    SetBackspace { backspace: char },
    /// Read backspace character
    GetBackspace,
    /// 4.11 Firmware update Over AT command (FOAT)\
    /// Force start of boot loader. The boot loader will start and be ready for an X-modem transfer at
    /// the defined baud rate
    FWUpdate {
        filetype: String<at::MaxCommandLen>,
        baud_rate: BaudRate,
    },
    /// 4.12 Module switch off\
    /// Reboot the DCE. During shut-down, settings marked for storing to start up database by are written in module's &W
    /// non-volatile memory
    PwrOff,
    /// 4.13 Module Start Mode\
    /// Write start mode
    SetStartMode { start_mode: Mode },
    /// Read start mode
    GetStartMode,
    /// 4.14 Local Address\
    /// Read the local address of the interface id
    GetLocalAddr { interface_id: InterfaceId },
    /// 4.15 System Status\
    /// Read current status of the system
    GetSystemStatus,
    /// 4.16 RS232 Settings\
    /// This command reads current RS232 settings from the Serial Port Adapter
    GetRS232Settings,
    /// This command applies new RS232 settings to the Serial Port Adapter. If 5, 6 or 7 data bits are selected
    /// the Serial Port Adapter will not change its RS232 settings until the next power cycle. If the command is
    /// successful, the baud rate is changed after the response. Wait 40ms from that the response is received
    /// before sending a new command to the Serial Port Adapter
    SetRS232Settings {
        baud_rate: BaudRate,
        flow_control: FlowControl,
        data_bits: u8,
        stop_bits: StopBits,
        parity: Parity,
        change_after_confirm: ChangeAfterConfirm,
    },
    /// 4.17 Route radio signals to GPIOs \
    /// Enable routing of radio signals to EXT_TX_EN and EXT_RX_EN pins.
    /// When routing is enabled on both the pins, it is recommended not to use other
    /// GPIO commands on the same pins to avoid undefined behavior
    #[cfg(feature = "nina_b3xx")]
    SetRouteRadioSignals { mode: u8 },
    /// Read if the radio signals are routed on the EXT_TX_EN and EXT_RX_EN pins
    #[cfg(feature = "nina_b3xx")]
    GetRouteRadioSignals,
    /// 4.18 Power regulator \
    /// Enable/disable automatic switch between DC/DC and LDO power regulators
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b3xx"))]
    SetPowerRegulators { value: u8 },
    /// Reads power regulator setting
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b3xx"))]
    GetPowerRegulators,
    /// 4.19 LPO detection \
    /// Checks if Low Power Oscillator (LPO) is detected or not
    #[cfg(feature = "odin_w2xx")]
    GetLPODetection,

    // 5 Data Mode Commands
    /// 5.1 Enter Data Mode\
    /// Request the Serial Port Adapter to move to new mode
    SetMode { mode: Mode },
    /// 5.2 Connect Peer\
    /// Connect to an enabled service on a remote device\
    /// When the host connects to a service on a remote device it implicitly registers to receive the "Connection Closed"
    /// event
    ConnectPeer { url: String<at::MaxCommandLen> },
    /// 5.3 Close Peer Connection\
    /// Close an existing peer connection
    ClosePeerConnection { peer_handle: u8 },
    /// 5.4 Default Remote Peer\
    /// This command reads the default remote peer (peer id)
    GetDefaultPeer { peer_id: u8 },
    /// This command writes the default remote peer (peer id)
    SetDefaultPeer {
        peer_id: u8,
        url: String<at::MaxCommandLen>,
        connect_scheme: u8,
    },
    /// 5.5 Peer list \
    /// This command reads the connected peers (peer handle)
    GetPeerList,
    // /// 5.6 Server Configuration \
    // /// Write server configuration
    // SetServerCfg(u8, u8),
    // /// Read server configuration
    // GetServerCfg(u8),
    /// 5.7 Server flags \
    /// Writes flags to a server.
    SetServerFlags { id: u8, flags: u8 },
    /// Reads flags from a server.
    GetServerFlags { id: u8 },
    /// 5.8 Watchdog Settings\
    /// Read current watchdog settings
    GetWatchdogSettings { wd_type: WatchDogType },
    /// Write watchdog parameters
    SetWatchdogSettings { wd_type: WatchDogType, timeout: u32 },
    /// 5.9 Configuration\
    /// Read peer configuration
    GetPeerConfig { param: PeerConfigGet },
    /// Write peer configuration
    SetPeerConfig { param: PeerConfigSet },
    /// 5.12 Bind \
    /// Binds TX data from Stream 1 to RX of Stream 2 and vice versa. Stream ids are
    /// provided on response of a successful connection
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    SetBind { stream_id_1: u8, stream_id_2: u8 },
    /// Reads current bindings.
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    GetBinds,
    /// 5.13 Bind to channel \
    /// Binds Stream with Id <StreamId> to channel with Id <ChannelId>. Stream ids are
    /// provided on response of a successful connection. Channel id is provided on response
    /// of a successful bind command
    #[cfg(feature = "odin_w2xx")]
    BindToChannel { stream_id: u8, channel_id: u8 },

    // 6 Bluetooth Commands
    /// 6.1 Discoverability Mode\
    /// Reads the GAP discoverability mode
    GetDiscoverable,
    /// Writes the GAP discoverability mode
    SetDiscoverable {
        discoverability_mode: DiscoverabilityMode,
    },
    /// 6.2 Connectability Mode\
    /// Reads the GAP connectability mode
    GetConnectability,
    /// Writes the GAP connectability mode
    SetConnectability {
        connectability_mode: ConnectabilityMode,
    },
    /// 6.3 Pairing Mode\
    /// Reads the pairing mode
    GetParingMode,
    /// Writes the pairing mode
    SetParingMode { pairing_mode: PairingMode },
    /// 6.4 Security Mode\
    /// Reads the security mode
    GetSecurityMode,
    /// Writes the security mode
    SetSecurityMode {
        security_mode: SecurityMode,
        security_mode_bt2_0: SecurityModeBT2_0,
        /// The BT 2.0 fixed_pin is a string of one to sixteen alphanumerical characters.\
        /// It is recommended to use a pin code of at least eight characters of mixed type, e.g. "12w35tg7".\
        /// Factory default is "0"
        fixed_pin: String<at::MaxCommandLen>,
    },
    /// 6.5 Security type \
    /// Reads the security type for Bluetooth pairing
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b2xx",))]
    GetSecurityType,
    /// Writes the security type for Bluetooth pairing
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b2xx",))]
    SetSecurityType { security_type: SecurityType },

    /// 6.6 User Confirmation\
    /// The user confirmation is used together with security mode "display yes/no" to respond on a user
    /// confirmation request (+UUBTUC). The command should only be used after +UUBTUC has been
    /// received
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    UserConfirmation {
        /// The remote Bluetooth Device address
        bd_addr: String<at::MaxCommandLen>,
        /// false: No. The remote and local values are different or the user cancels.\
        /// true: Yes. The remote and local values are the same
        yes_no: bool,
    },
    /// 6.7 User Passkey Entry\
    /// The user passkey entry is used together with security mode "keyboard only" to
    /// respond on a user passkey entry request (+UUBTUPE). The command should
    /// only be used after +UUBTUPE has been received
    UserPasskey {
        /// The remote Bluetooth Device address
        bd_addr: String<at::MaxCommandLen>,
        /// false: Cancel\
        /// true: Ok
        ok_cancel: bool,
        /// This is an integer in the range of [0..999999].
        passkey: u16,
    },
    /// 6.8 OOB temporary key \
    /// Reads the OOB temporary key
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b2xx",))]
    GetOOBTempKey,
    /// Writes the OOB temporary key
    #[cfg(any(feature = "nina_b1xx", feature = "anna_b1xx", feature = "nina_b2xx",))]
    SetOOBTempKey {
        mode: OOBMode,
        temp_key: Vec<u8, consts::U8>,
    },
    /// 6.9 Name Discovery\
    /// Retrieves the device name of a remote device given its Bluetooth device
    NameDiscovery {
        /// Local name of remote device of maximum 240 characters (8-bit ASCII)
        device_name: String<at::MaxCommandLen>,
        mode: BTMode,
        /// Timeout measured in milliseconds, only applicable for BT Classic
        /// Time Range: 10 ms - 40 s
        /// Default: 5000 ms
        timeout: u16,
    },
    /// 6.10 Inquiry \
    /// Performs an inquiry procedure to find any discoverable devices in the vicinity
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    Inquiry {
        inquiry_type: InquiryType,
        /// Timeout measured in milliseconds\
        /// Time Range: 10 ms - 40 s, default 5000 ms
        inquiry_length: u8,
    },
    /// 6.11 Discovery (Low Energy)\
    /// Performs an inquiry procedure to find any discoverable devices in the vicinity
    Discovery {
        discovery_type: DiscoveryType,
        mode: DiscoveryMode,
        /// Timeout measured in milliseconds\
        /// Time Range: 10 ms - 40 s, default 5000 ms
        inquiry_length: u8,
    },
    /// 6.12 Bond\
    /// Performs a GAP bond procedure with another Bluetooth device.
    /// During the bonding procedure user interaction is required. Which procedure to use is determined by
    /// the security mode. For user interaction during bonding see User Confirmation +UBTUC User and
    /// Passkey Entry +UBTUPE commands and User Confirmation +UUBTUC User Passkey Entry and
    /// +UUBTUPE events. Note that to be able to perform bonding the remote device must be in pairable
    /// and connectable mode. When the bond is complete a Bond Event +UUBTB is generated
    Bond {
        /// Bluetooth device address of the device to bond with
        bd_addr: String<at::MaxCommandLen>,
        mode: BTMode,
    },
    /// 6.13 Un-bond\
    /// This command un-bonds a previously bonded device
    UnBond {
        /// Bluetooth device address of the device subject to un-bond.\
        /// If address FFFFFFFFFFFF is selected all bonded devices will be removed
        bd_addr: String<at::MaxCommandLen>,
    },
    /// 6.14 Read Bonded Devices\
    /// Read the bonded devices
    GetBonds { mode: BTMode },
    /// 6.15 Local Name\
    /// Reads the local Bluetooth device name
    GetLocalName,
    /// Writes the local Bluetooth device name
    SetLocalName {
        /// Max 31 characters.\
        /// The default name is "Bluetooth Device".
        device_name: String<at::MaxCommandLen>,
    },
    /// 6.16 Local COD\
    /// Reads the Local Class Of Device code
    GetLocalCOD,
    /// Writes the Local Class Of Device code
    SetLocalCOD {
        /// Valid values for this parameter are specified in the Bluetooth Assigned Numbers Document, www.bluetoot
        /// h.com. The parameter has been divided into three segments, a service class segment, a major device
        /// class segment and a minor device class segment (bits 2-7).\
        /// Extract from the Bluetooth Assigned Numbers Document:\
        /// Service class (bit mask, bits 13-23):\
        /// Bit 16: Positioning (Location identification)\
        /// Bit 17: Networking (LAN, Ad hoc, etc)\
        /// Bit 18: Rendering (Printing, Speaker, etc)\
        /// Bit 19: Capturing (Scanner, Microphone, etc)\
        /// Bit 20: Object Transfer (v-Inbox, v-Folder, etc)\
        /// Bit 21: Audio (Speaker, Microphone, Headset service, etc)\
        /// Bit 22: Telephony (Cordless telephony, Modem, Headset service)\
        /// Bit 23: Information (WEB-server, WAP-server, etc)\
        /// Major device class (number, bits 12-8):\
        /// 00000: Miscellaneous\
        /// 00001: Computer (desktop, notebook, PDA, etc)\
        /// 00010: Phone (cellular, cordless, modem, etc)\
        /// 00011: LAN/Network Access point\
        /// 00100: Audio/Video (headset, speaker, stereo, video display, VCR)\
        /// 00101: Peripheral (mouse, joystick, keyboards)\
        /// 00110: Imaging (printing, scanner, camera, etc)\
        /// 11111: Uncategorized, specific device code not specified\
        /// The default value is 0.
        cod: Vec<u8, consts::U5>,
    },
    /// 6.17 Master Slave Role\
    /// Read the local master-slave role.
    /// Returns the role of the Serial Port Adapter, master or slave, for the connection between the Serial Port Adapter and
    /// the remote device identified by the 'bd_addr' parameter
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    GetMasterSlaveRole {
        ///  Identifies a device that the Serial Port Adapter is currently communicating with
        bd_addr: String<at::MaxCommandLen>,
    },
    /// 6.18 Master Slave Role Policy\
    /// Reads the role policy of the device
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    GetRolePolicy,
    /// Writes the role policy of the device
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    SetRolePolicy {
        /// false: Always attempt to become master on incoming connections.
        /// true: Always let the connecting device select master/slave role on incoming connections. (factory default)
        role_policy: bool,
    },
    /// 6.19 Get RSSI\
    /// This request returns the current received signal strength, RSSI, for the connection between the Serial Port Adapter
    /// and the remote device identified by the 'bd_addr' parameter
    GetRSSI {
        /// Identifies a device that the Serial Port Adapter is currently communicating with
        bd_addr: String<at::MaxCommandLen>,
    },
    /// 6.20 Get Link Quality\
    /// This request returns the current link quality for the connection between the Serial Port Adapter and the remote
    /// device identified by the <bd_addr> parameter
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    GetLinkQuality {
        /// Identifies a device that the Serial Port Adapter is currently communicating with
        bd_addr: String<at::MaxCommandLen>,
    },
    /// 6.21 Bluetooth Low Energy Role\
    /// Reads the configuration status
    GetRoleConfiguration,
    /// Writes the configuration status
    SetRoleConfiguration { role: BTRole },
    /// 6.22 Low Energy Advertise Data\
    /// Read custom advertise data
    GetLEAdvertiseData,
    /// Write custom advertise data
    SetLEAdvertiseData {
        /// Custom advertise data. Maximum 28 bytes.\
        /// The default value includes AD Flags, Tx power, Slave connection interval and the u-blox Serial Service\
        /// UUID.\
        /// It is recommended to use the u-blox Serial Service UUID (2456e1b926e28f83e744f34f01e9d701) for\
        /// filtering when doing scan in smartphone apps.\
        /// The data must follow the Bluetooth Specification. Data is divided into different\
        /// consecutive data blocks, where each block has the following structure:\
        /// Byte 0: Length of data block, N, excluding length byte.\
        /// Byte 1: GAP advertisement data type, see below.\
        /// Byte 2-N: Data.\
        /// Typical GAP advertisement data types:\
        /// 0x01 AD Flags (Mandatory for advertising data)\
        /// 0x02 16-bit Service UUIDs, more available\
        /// 0x03 16-bit Service UUIDs, complete list\
        /// 0x04 32-bit Service UUIDs, more available\
        /// 0x05 32-bit Service UUIDs, complete list\
        /// 0x06 128-bit Service UUIDs, more available\
        /// 0x07 128-bit Service UUIDs, complete list\
        /// 0x08 Shortened Local name\
        /// 0x09 Complete Local Name\
        /// 0x0A Tx Power in dBm\
        /// 0x12 Slave connection interval range\
        /// 0xFF Manufacturer Specific Data (The first 2 octets contain the Company Identifier Code followed by\
        /// additional manufacturer specific data)\
        /// Example: "07FF710000112233", where "07" is the length, "FF" is the GAP advertisement data type\
        /// "Manufacturer Specific Data" and "7100" is the u-blox Company Identifier written with lowest octet first and\
        /// "00112233" is the application data
        data: Vec<u8, consts::U8>,
    },
    /// 6.23 Low Energy Scan Response Data\
    /// Read scan response data
    GetLEScanResponseData,
    /// Write scan response data
    SetLEScanResponseData {
        /// Custom scan response data. Maximum 31 bytes.\
        /// The default value includes the complete local name of device.\
        /// Same format as data parameter of the AT+UBTAD command
        data: Vec<u8, consts::U8>,
    },
    /// 6.24 Service Search\
    /// Search for services on a remote device
    #[cfg(any(feature = "odin_w2xx", feature = "nina_w1xx", feature = "nina_b2xx",))]
    ServiceSearch {
        /// Bluetooth device address of the device on which to search for services
        bd_addr: String<at::MaxCommandLen>,
        service_type: ServiceType,
        /// 16 values
        uuid: Vec<u8, consts::U8>,
    },
    // /// 6.25 Watchdog Settings\
    // /// Write watchdog parameter
    // TODO:
    // #[cfg(feature = "odin_w2xx")]
    // GetWatchdogParameter(u8),
    // /// Read watchdog parameter(s)
    // #[cfg(feature = "odin_w2xx")]
    // SetWatchdogParameter(u8, u8),
    // /// 6.26 Bluetooth Configuration\
    // /// Read Bluetooth configuration
    // GetBTConfig(u8),
    // /// Write Bluetooth configuration
    // SetBTConfig(u8, u8),
    // /// 6.27 Bluetooth Low Energy Configuration\
    // /// Read Bluetooth LE configuration
    // GetBTLEConfig(u8),
    // /// Write Bluetooth LE configuration
    // SetBTLEConfig(u8, u8),
    /// 6.28 Device ID record \
    /// Read device record
    // #[cfg(any(
    //     feature = "odin_w2xx",
    //     feature = "nina_w1xx",
    //     feature = "nina_b2xx",
    // ))]
    //     GetDeviceRecord,
    //     SetDeviceRecord,

    /// 6.46 Bluetooth low energy PHY Update \
    /// Informs the result of a PHY update procedure. It may be generated as a result of
    /// the command AT+UBTLEPHYR or as a successful event, if the operation has been
    /// initiated by the remote peer
    // #[cfg(any(
    //     feature = "nina_b1xx",
    //     feature = "anna_b1xx",
    //     feature = "nina_b3xx",
    // ))]
    // BLEPhyUpdate {

    // },

    // 7 Wi-Fi
    /// 7.1 Wi-Fi Station Configuration\
    /// Read Wi-Fi station configuration
    STAGetConfig {
        configuration_id: ConfigId,
        param_tag: UWSCGetTag,
    },
    /// Set Wi-Fi station configuration
    STASetConfig {
        configuration_id: ConfigId,
        param_tag: UWSCSetTag,
    },
    /// 7.2 Wi-Fi Station Configuration Action\
    /// Execute an action for the Wi-Fi Network
    ExecSTAAction {
        configuration_id: ConfigId,
        action: STAAction,
    },
    /// 7.3 Wi-Fi Active Station Configuration List\
    /// List active network configurations
    STAGetConfigList,
    /// 7.4 Scan\
    /// Scan the surroundings for networks. The command will return networks in the immediate surroundings, then
    /// return OK or ERROR if not able to start scan. Channels scanned is given by the channel list, see +UWCL for
    /// more information. If SSID is defined a directed scan will be performed.
    STAScan {
        ssid: Option<String<at::MaxCommandLen>>,
    },
    /// 7.5 Channel List\
    /// Write the wanted channel list for station mode
    /// The channel list is restored to default value by passing the command without parameters: AT+UWCL
    STASetChannelList { channel_list: Vec<u8, consts::U8> },
    /// Read the wanted channel list
    STAGetChannelList,
    /// 7.6 Wi-Fi Watchdog Settings\
    /// Read watchdog parameter, if type is omitted, all parameters are read
    WIFIGetWatchdogParameter { wd_type: WIFIWatchDogTypeGet },
    /// Write watchdog parameters
    WIFISetWatchdogParameter { wd_type: WIFIWatchDogTypeSet },
    /// 7.7 Wi-Fi Station Status
    /// Read current status of the Wi-Fi interface
    STAGetStatus { status_id: STAStatus },

    // 8 Ethernet
    // 9 Point-to-Point protocol
    // 10 Network
    /// 10.1 Network Host Name\
    /// Read current Host Name. Default: "odin-w2-xxxxxxxxxxxx", where "xxxxxxxxxxxx" is a device specific number
    GetHostname,
    /// Set a new host name, parameter must be a string with maximum 64 charaters
    SetHostname { hostname: String<at::MaxCommandLen> },
    /// 10.2 Network Status\
    /// Show current status of network configuration id
    GetNetworkStatus {
        interface_type: InterfaceType,
        status_id: StatusId,
    },
    // 11 Security
    // 12 GATT server
    // 13 GATT client
    // 14 GPIO
    // 15 NFC
    // 16 PING
    // 17 Javascript
    // 18 File system
}
