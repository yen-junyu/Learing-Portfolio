pragma solidity >=0.4.22 <0.8.0;
import "./PersonalIdentity.sol";
pragma experimental ABIEncoderV2;

contract IdentityManager {
    constructor() public {
         for (uint i = 0; i < _orgsArr.length; i++) {
             _orgs[_orgsArr[i]] = true;
         }
    }
    modifier onlyOrg {
        require(_orgs[msg.sender],
                "Only organization administrator can call.");
        _;
    }
    struct UserInfo {
        address lastModifyOrg;          // [org2.id]
        address personalIdentityAddress;   // address of access control manager
        address userAddress;            // binding addrss
        mapping(address => bool) orgs;  // [org1.id, org2.id]
    }

    address[] _orgsArr = [0xe092b1fa25DF5786D151246E492Eed3d15EA4dAA];
    mapping (address => bool) _orgs;
    mapping(string => UserInfo) _uniqueIdenity; // hash(id) map userAcc
    mapping(string => bool) _uniqueState; // hash(id) is added by orgs 
    mapping(address => string) _bindUsers; // address map hash(id)
    mapping(string => bool) _bindState; // hash(id) not bind
  

    event AddUserEvent(address orgAddress, uint status);
    event BindUserAccountEvent(address orgAddress, address userAccount, string hashed);

    function addUser(string memory hashed) public onlyOrg
    {
        //bytes32 hashed = keccak256(bytes(uniqueId));
        //string memory hashed = uniqueId;
        //bytes32 hashed = bytes(uniqueId);
        if (_uniqueState[hashed]) {
            // alreay exist and add org
            _uniqueIdenity[hashed].orgs[msg.sender] = true;
            _uniqueIdenity[hashed].lastModifyOrg = msg.sender;
            emit AddUserEvent(msg.sender, 0);
        }
        else {
            _uniqueState[hashed] = true;
            UserInfo memory info = UserInfo(
                                        msg.sender,
                                        address(0),
                                        address(0)
                                    );
            _uniqueIdenity[hashed] = info;
            _uniqueIdenity[hashed].orgs[msg.sender] = true;
            emit AddUserEvent(msg.sender, 1);
        }
    }

    function bindAccount(string memory hashed,address userAddress) public onlyOrg
    {
        //bytes memory tempEmptyStringTest = bytes(emptyStringTest);
        require(bytes(_bindUsers[userAddress]).length == 0,
                "This address already binded.");
        require(_bindState[hashed] == false,
                "This UniqueId already binded");
        require(_uniqueState[hashed],
                "UniqueId invalid.");
        //string hashed = uniqueId;

        _bindUsers[userAddress] = hashed;    // for record address <==> hashed id
        _bindState[hashed] = true;           // for confirm this hashed id already bind before

        // create contract and transfer ownership to user himself
        PersonalIdentity personalIdentity = new PersonalIdentity();
        personalIdentity.transferOwnership(userAddress);
        
        // update user info
        _uniqueIdenity[hashed].personalIdentityAddress = address(personalIdentity);
        _uniqueIdenity[hashed].userAddress = userAddress;
        
        emit BindUserAccountEvent(msg.sender, userAddress, hashed);
    }

    function getAccessManagerAddress(address userAddress) public view returns (address) {
        return _uniqueIdenity[_bindUsers[userAddress]].personalIdentityAddress;
    }

    function getId() public view returns (string memory) {
        return _bindUsers[msg.sender];
    }
    
}