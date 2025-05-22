pragma solidity >= 0.4.0 <= 0.9;
pragma experimental ABIEncoderV2;
//Encryption solidity code
contract Encryption {

    uint public userCount = 0; 
    mapping(uint => user) public userList; 
     struct user
     {
       string username;
       string password;
       string phone;
       string email;
       string home_address;
     }
 
   // events 
   event userCreated(uint indexed _userId);
   
   //function  to save user details to Blockchain
   function saveUser(string memory uname, string memory pass, string memory phone, string memory email, string memory ha) public {
      userList[userCount] = user(uname, pass, phone, email, ha);
      emit userCreated(userCount);
      userCount++;
    }

     //get user count
    function getUserCount()  public view returns (uint) {
          return  userCount;
    }

    uint public keysCount = 0; 
    mapping(uint => keys) public keysList; 
     struct keys
     {
       string key_id;
       string key_hash;
       string image;
       string sender;
       string receiver;
       string upload_date;       
     }
 
   // events 
   event keysCreated(uint indexed _keysId);
   
   //function  to save keysdetails to Blockchain
   function saveKeys(string memory kid, string memory kh, string memory img, string memory sen, string memory rec,string memory udate) public {
      keysList[keysCount] = keys(kid,  kh, img, sen, rec, udate);
      emit keysCreated(keysCount);
      keysCount++;
    }

    //get keys count
    function getKeyCount()  public view returns (uint) {
          return  keysCount;
    }

    function getUsername(uint i) public view returns (string memory) {
        user memory doc = userList[i];
	return doc.username;
    }

    function getPassword(uint i) public view returns (string memory) {
        user memory doc = userList[i];
	return doc.password;
    }

    function getPhone(uint i) public view returns (string memory) {
        user memory doc = userList[i];
	return doc.phone;
    }    

    function getEmail(uint i) public view returns (string memory) {
        user memory doc = userList[i];
	return doc.email;
    }

    function getAddress(uint i) public view returns (string memory) {
        user memory doc = userList[i];
	return doc.home_address;
    }

    function getKeyid(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.key_id;
    }

    function getHash(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.key_hash;
    }

    function getImage(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.image;
    }

    function getUploadDate(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.upload_date;
    }

    function getSender(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.sender;
    }

    function getReceiver(uint i) public view returns (string memory) {
        keys memory doc = keysList[i];
	return doc.receiver;
    }
        
}