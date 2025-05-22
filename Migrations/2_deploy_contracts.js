const Encryption = artifacts.require("Encryption");

module.exports = function(deployer) {
  deployer.deploy(Encryption);
};
