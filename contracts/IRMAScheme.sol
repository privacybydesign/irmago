pragma solidity 0.4.20;
//import "github.com/willitscale/solidity-util/lib/Strings.sol";
// import './Strings.sol';


contract IRMAScheme {
    // using Strings for string;

    struct IssuerPublicKey {
        uint id;
        bytes key;
    }

    struct Credential {
        bool exists;

        string id;
        string logoUrl;
        bytes issueSpec;
    }

    struct Issuer {
        bool exists;

        string id;
        string logoUrl;
        address owner;
        bytes metadata;

        mapping (uint => IssuerPublicKey) publicKeys;
        uint numPublicKeys;

        mapping (string => Credential) credentials;
        string[] credentialIds;
    }

    string public id;
    address public owner;
    bytes public metadata;

    mapping (string => Issuer) private issuers;
    string[] public issuerIds;

    function IRMAScheme(string _id, bytes _metadata) public {
        owner = msg.sender;
        id = _id;
        metadata = _metadata;
    }

    function getNumberOfIssuers() public view returns (uint) {
        return issuerIds.length;
    }

    function addIssuer( string _id,
                        string _logoUrl,
                        bytes _metadata) public returns (bool) {
        if (bytes(_id).length == 0) { //issuerId should be a non empty string
            return false;
        }
        if (issuers[_id].exists) { //no issuer with that id should exist
            return false;
        }
        issuers[_id] = Issuer(true, _id, _logoUrl, msg.sender, _metadata, 0, new string[](0));
        issuerIds.push(_id);
        return true;
    }

    function getIssuerById(string _id) public view returns (string, string, address, bytes, uint, uint) {
        Issuer storage issuer = issuers[_id];
        if (issuer.exists) {
            return (issuer.id, issuer.logoUrl, issuer.owner,
                    issuer.metadata, issuer.numPublicKeys, issuer.credentialIds.length);
        }
    }

    function addIssuerPublicKey(string _issuerId, bytes _key) public returns (bool) {
        Issuer storage issuer = issuers[_issuerId];
        if (!issuer.exists) { //issuer should exist
            return false;
        }
        if (issuer.owner != msg.sender) { //only owner can add public keys
            return false;
        }
        issuer.publicKeys[issuer.numPublicKeys] = IssuerPublicKey(issuer.numPublicKeys, _key);
        issuer.numPublicKeys++;
        return true;
    }

    function getIssuerPublicKeyById(string _issuerId, uint _keyIndex) public view returns (uint, bytes) {
        Issuer storage issuer = issuers[_issuerId];
        if (!issuer.exists) { //issuer should exist
            revert();
        }
        if (_keyIndex >= issuer.numPublicKeys) { //key should exist
            revert();
        }
        IssuerPublicKey storage key = issuer.publicKeys[_keyIndex];
        return (key.id, key.key);
    }

    function addIssuerCredential(string _issuerId,
                                string _credentialId, string _logoUrl, bytes _issueSpec) public returns (bool) {
        Issuer storage issuer = issuers[_issuerId];
        if (!issuer.exists) { //issuer should exist
            return false;
        }
        if (issuer.owner != msg.sender) { //only owner can add credentials
            return false;
        }
        issuer.credentials[_credentialId] = Credential(true, _credentialId, _logoUrl, _issueSpec);
        issuer.credentialIds.push(_credentialId);
        return true;
    }

    function getIssuerCredentialById(string _issuerId, string _credId) public view returns (string, string, bytes) {
        Issuer storage issuer = issuers[_issuerId];
        if (!issuer.exists) { //issuer should exist
            revert();
        }
        Credential storage credential = issuer.credentials[_credId];
        if (!credential.exists) { //credential should exist
            revert();
        }
        return (credential.id, credential.logoUrl, credential.issueSpec);
    }

    function getIssuerCredentialIdByCredentialIndex(string _issuerId, uint _credIndex) public view returns (string, string, bytes) {
        Issuer storage issuer = issuers[_issuerId];
        if (!issuer.exists) { //issuer should exist
            revert();
        }
        if (_credIndex >= issuer.credentialIds.length) { //credentialId should exist
            revert();
        }
        string storage _credId = issuer.credentialIds[_credIndex];
        Credential storage credential = issuer.credentials[_credId];
        if (!credential.exists) { //credential should exist
            revert();
        }
        return (credential.id, credential.logoUrl, credential.issueSpec);
    }

    // function getSchemaJSON() public view returns (string) {
    //     return getSchemaIssuerIdsJson();
    // }

    // function getSchemaIssuerIdsJson() private view returns (string) {
    //     string memory json = "{";
    //     json = json.concat("issuers: [");
    //     for (uint i = 0; i < issuerIds.length; ++i) {
    //         json = json.concat("\"").concat(issuerIds[i]).concat("\"");
    //     }
    //     json = json.concat("]}");
    //     return json;
    // }

}
