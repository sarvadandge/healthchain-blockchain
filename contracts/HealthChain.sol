// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title HealthChain
 * @notice Merged contract for:
 *   - IoT sensor data storage + tamper detection
 *   - Patient report upload (encrypted, off-chain on IPFS)
 *   - Doctor access control
 *   - Emergency contacts (max 3 per patient)
 *   - Owner bypass for backend reads
 */
contract HealthChain {

    // ─────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────

    struct SensorRecord {
        uint256 sensorId;
        string  ipfsCID;
        string  dataHash;
        string  dataType;
        address uploader;
        uint256 timestamp;
        bool    isVerified;
    }

    struct Report {
        uint256 reportId;
        string  patientId;
        string  ipfsCID;
        string  fileHash;
        string  reportType;
        string  nonce;
        address uploadedBy;
        uint256 timestamp;
        bool    isActive;
    }

    struct EmergencyContact {
        address wallet;
        string  name;
        string  relation;
        bool    isActive;
    }

    // ─────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────

    address public owner;

    // ── Sensor ──
    uint256 public sensorRecordCount;
    mapping(uint256 => SensorRecord[]) private sensorHistory;
    mapping(uint256 => SensorRecord)   private allSensorRecords;

    // ── Reports ──
    uint256 public reportCount;
    mapping(string  => Report[])   private patientReports;
    mapping(uint256 => Report)     private allReports;

    // ── Access ──
    mapping(string => address)                        private patientWallet;
    mapping(string => mapping(address => bool))       private doctorAccess;
    mapping(string => EmergencyContact[])             private emergencyContacts;

    // ─────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────

    event SensorDataStored(
        uint256 indexed recordId,
        uint256 indexed sensorId,
        string  ipfsCID,
        string  dataHash,
        string  dataType,
        address uploader,
        uint256 timestamp
    );

    event TamperDetected(
        uint256 indexed sensorId,
        string  storedHash,
        string  computedHash,
        uint256 timestamp
    );

    event DataVerified(
        uint256 indexed sensorId,
        bool    isValid,
        uint256 timestamp
    );

    event ReportUploaded(
        uint256 indexed reportId,
        string  patientId,
        string  ipfsCID,
        string  fileHash,
        string  reportType,
        address uploadedBy,
        uint256 timestamp
    );

    event DoctorAccessGranted(string patientId, address doctor, uint256 timestamp);
    event DoctorAccessRevoked(string patientId, address doctor, uint256 timestamp);

    event EmergencyContactAdded(
        string  patientId,
        address contactWallet,
        string  name,
        string  relation,
        uint256 timestamp
    );

    event EmergencyContactRemoved(
        string  patientId,
        address contactWallet,
        uint256 timestamp
    );

    // ─────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ─────────────────────────────────────────────────────────
    // Modifiers
    // ─────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /**
     * @dev Patient guard — allows first-time registration by anyone,
     *      then locks to the registered wallet.
     *      Owner is always allowed (backend needs to upload on behalf).
     */
    modifier onlyPatientOrOwner(string memory _patientId) {
        require(
            msg.sender == owner                              ||
            patientWallet[_patientId] == address(0)         ||
            patientWallet[_patientId] == msg.sender,
            "Not authorized: not the patient"
        );
        _;
    }

    /**
     * @dev Read guard — owner, patient, granted doctor, or emergency contact.
     */
    modifier hasAccess(string memory _patientId) {
        require(
            msg.sender == owner                              ||
            patientWallet[_patientId] == msg.sender          ||
            doctorAccess[_patientId][msg.sender]             ||
            _isEmergencyContact(_patientId, msg.sender),
            "Access denied"
        );
        _;
    }

    // ─────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────

    function _isEmergencyContact(string memory _patientId, address _addr)
        internal view returns (bool)
    {
        EmergencyContact[] storage contacts = emergencyContacts[_patientId];
        for (uint256 i = 0; i < contacts.length; i++) {
            if (contacts[i].wallet == _addr && contacts[i].isActive) return true;
        }
        return false;
    }

    function _registerPatient(string memory _patientId) internal {
        if (patientWallet[_patientId] == address(0)) {
            patientWallet[_patientId] = msg.sender;
        }
    }

    // ─────────────────────────────────────────────────────────
    // ── SENSOR DATA ──────────────────────────────────────────
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Store IoT sensor data hash + IPFS CID on-chain.
     */
    function storeSensorData(
        uint256 _sensorId,
        string  memory _ipfsCID,
        string  memory _dataHash,
        string  memory _dataType
    ) public {
        require(bytes(_ipfsCID).length  > 0, "Empty CID");
        require(bytes(_dataHash).length > 0, "Empty hash");
        require(bytes(_dataType).length > 0, "Empty type");

        SensorRecord memory record = SensorRecord({
            sensorId:   _sensorId,
            ipfsCID:    _ipfsCID,
            dataHash:   _dataHash,
            dataType:   _dataType,
            uploader:   msg.sender,
            timestamp:  block.timestamp,
            isVerified: false
        });

        sensorHistory[_sensorId].push(record);
        allSensorRecords[sensorRecordCount] = record;

        emit SensorDataStored(
            sensorRecordCount, _sensorId, _ipfsCID,
            _dataHash, _dataType, msg.sender, block.timestamp
        );

        sensorRecordCount++;
    }

    /**
     * @notice Verify integrity — compare on-chain hash with recomputed hash.
     */
    function verifySensorIntegrity(
        uint256 _sensorId,
        uint256 _recordIndex,
        string  memory _computedHash
    ) public returns (bool) {
        require(
            _recordIndex < sensorHistory[_sensorId].length,
            "Record does not exist"
        );

        SensorRecord storage record = sensorHistory[_sensorId][_recordIndex];

        bool isValid = keccak256(bytes(record.dataHash)) ==
                       keccak256(bytes(_computedHash));

        record.isVerified = isValid;

        if (!isValid) {
            emit TamperDetected(
                _sensorId, record.dataHash, _computedHash, block.timestamp
            );
        }

        emit DataVerified(_sensorId, isValid, block.timestamp);
        return isValid;
    }

    // ── Sensor getters ──

    function getLatestSensorRecord(uint256 _sensorId)
        public view returns (SensorRecord memory)
    {
        uint256 len = sensorHistory[_sensorId].length;
        require(len > 0, "No records for this sensor");
        return sensorHistory[_sensorId][len - 1];
    }

    function getSensorRecord(uint256 _sensorId, uint256 _index)
        public view returns (SensorRecord memory)
    {
        require(_index < sensorHistory[_sensorId].length, "Record does not exist");
        return sensorHistory[_sensorId][_index];
    }

    function getSensorHistory(uint256 _sensorId)
        public view returns (SensorRecord[] memory)
    {
        return sensorHistory[_sensorId];
    }

    function getSensorRecordCount(uint256 _sensorId)
        public view returns (uint256)
    {
        return sensorHistory[_sensorId].length;
    }

    // ─────────────────────────────────────────────────────────
    // ── PATIENT REPORTS ──────────────────────────────────────
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Upload encrypted report — stores CID + hash + nonce on-chain.
     */
    function uploadReport(
        string memory _patientId,
        string memory _ipfsCID,
        string memory _fileHash,
        string memory _reportType,
        string memory _nonce
    ) public onlyPatientOrOwner(_patientId) {
        _registerPatient(_patientId);

        Report memory report = Report({
            reportId:   reportCount,
            patientId:  _patientId,
            ipfsCID:    _ipfsCID,
            fileHash:   _fileHash,
            reportType: _reportType,
            nonce:      _nonce,
            uploadedBy: msg.sender,
            timestamp:  block.timestamp,
            isActive:   true
        });

        patientReports[_patientId].push(report);
        allReports[reportCount] = report;

        emit ReportUploaded(
            reportCount, _patientId, _ipfsCID,
            _fileHash, _reportType, msg.sender, block.timestamp
        );

        reportCount++;
    }

    // ── Report getters ──

    function getPatientReports(string memory _patientId)
        public view hasAccess(_patientId)
        returns (Report[] memory)
    {
        return patientReports[_patientId];
    }

    function getReport(string memory _patientId, uint256 _reportId)
        public view hasAccess(_patientId)
        returns (Report memory)
    {
        require(_reportId < reportCount, "Report does not exist");
        return allReports[_reportId];
    }

    function getReportCount(string memory _patientId)
        public view returns (uint256)
    {
        return patientReports[_patientId].length;
    }

    // ─────────────────────────────────────────────────────────
    // ── DOCTOR ACCESS ─────────────────────────────────────────
    // ─────────────────────────────────────────────────────────

    function grantDoctorAccess(string memory _patientId, address _doctor)
        public onlyPatientOrOwner(_patientId)
    {
        doctorAccess[_patientId][_doctor] = true;
        emit DoctorAccessGranted(_patientId, _doctor, block.timestamp);
    }

    function revokeDoctorAccess(string memory _patientId, address _doctor)
        public onlyPatientOrOwner(_patientId)
    {
        doctorAccess[_patientId][_doctor] = false;
        emit DoctorAccessRevoked(_patientId, _doctor, block.timestamp);
    }

    function checkDoctorAccess(string memory _patientId, address _doctor)
        public view returns (bool)
    {
        return doctorAccess[_patientId][_doctor];
    }

    // ─────────────────────────────────────────────────────────
    // ── EMERGENCY CONTACTS ────────────────────────────────────
    // ─────────────────────────────────────────────────────────

    function addEmergencyContact(
        string  memory _patientId,
        address        _contactWallet,
        string  memory _name,
        string  memory _relation
    ) public onlyPatientOrOwner(_patientId) {
        require(_contactWallet != address(0), "Invalid wallet");

        EmergencyContact[] storage contacts = emergencyContacts[_patientId];
        uint256 activeCount = 0;

        for (uint256 i = 0; i < contacts.length; i++) {
            if (contacts[i].isActive) {
                activeCount++;
                require(contacts[i].wallet != _contactWallet, "Already added");
            }
        }

        require(activeCount < 3, "Max 3 emergency contacts");

        contacts.push(EmergencyContact({
            wallet:   _contactWallet,
            name:     _name,
            relation: _relation,
            isActive: true
        }));

        emit EmergencyContactAdded(
            _patientId, _contactWallet, _name, _relation, block.timestamp
        );
    }

    function removeEmergencyContact(
        string  memory _patientId,
        address        _contactWallet
    ) public onlyPatientOrOwner(_patientId) {
        EmergencyContact[] storage contacts = emergencyContacts[_patientId];
        bool found = false;

        for (uint256 i = 0; i < contacts.length; i++) {
            if (contacts[i].wallet == _contactWallet && contacts[i].isActive) {
                contacts[i].isActive = false;
                found = true;
                break;
            }
        }

        require(found, "Contact not found");
        emit EmergencyContactRemoved(_patientId, _contactWallet, block.timestamp);
    }

    function getEmergencyContacts(string memory _patientId)
        public view returns (EmergencyContact[] memory)
    {
        require(
            msg.sender == owner ||
            patientWallet[_patientId] == msg.sender,
            "Not authorized"
        );

        EmergencyContact[] storage contacts = emergencyContacts[_patientId];
        uint256 activeCount = 0;
        for (uint256 i = 0; i < contacts.length; i++) {
            if (contacts[i].isActive) activeCount++;
        }

        EmergencyContact[] memory active = new EmergencyContact[](activeCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < contacts.length; i++) {
            if (contacts[i].isActive) {
                active[idx] = contacts[i];
                idx++;
            }
        }
        return active;
    }

    function checkEmergencyContact(string memory _patientId, address _addr)
        public view returns (bool)
    {
        return _isEmergencyContact(_patientId, _addr);
    }

    // ─────────────────────────────────────────────────────────
    // ── ACCESS SUMMARY ────────────────────────────────────────
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Returns the caller's role for a patient.
     * Returns: "owner" | "patient" | "doctor" | "emergency_contact" | "none"
     */
    function getCallerRole(string memory _patientId)
        public view returns (string memory)
    {
        if (msg.sender == owner)                                return "owner";
        if (patientWallet[_patientId] == msg.sender)            return "patient";
        if (doctorAccess[_patientId][msg.sender])               return "doctor";
        if (_isEmergencyContact(_patientId, msg.sender))        return "emergency_contact";
        return "none";
    }
}
