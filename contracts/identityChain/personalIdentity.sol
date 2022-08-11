pragma solidity >=0.4.22 <0.8.0;

contract PersonalIdentity {
    // reference: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol
    address private _owner;
    mapping(string=>string) _encryptMaterial;
    
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event setEncryptMaterialEvent(string Material, address org, string EncryptObject);
    
    // remember to change public to internal
    constructor () public {
        address msgSender = msg.sender;
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }
    
    function owner() public view returns (address) {
        return _owner;
    }
    
    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function setEncryptMaterial(string memory Material, address org, string memory EncryptObject) public onlyOwner{
        _encryptMaterial[Material] = EncryptObject;
        emit setEncryptMaterialEvent(Material,org,EncryptObject);
    }

    function getEncryptMaterial(string memory Material) public view returns(string memory) {
        return _encryptMaterial[Material];
    }
}