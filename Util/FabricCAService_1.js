var FabricCAServices = require('fabric-ca-client');

const FabricCAServices_1 = class extends FabricCAServices {

    constructor(url, tlsOptions, caName, cryptoSuite) {
		super(url, tlsOptions, caName, cryptoSuite);
    }
    async createKeyAndCSR(subject){
        let privateKey;
		try {
			privateKey = await this.getCryptoSuite().generateKey();
		} catch (e) {
			throw Error(`Failed to generate key for enrollment due to error [${e}]: ${e.stack}`);
		}

		// generate CSR using the subject of the current user's certificate
		let csr;
		try {
			csr = privateKey.generateCSR('CN=' + subject);
		} catch (e) {
			throw Error(`Failed to generate CSR for enrollment due to error [${e}]`);
		}
        
        return {
            privateKey: privateKey._key.prvKeyHex, 
            publicKey: privateKey._key.pubKeyHex,
            csr: csr,
        }
    }
    async enrollWithCSR(req){
        const enrollResponse = await this._fabricCAClient.enroll(req.enrollmentID, req.enrollmentSecret, req.csr, req.profile, req.attr_reqs);
		const enrollment = {
			certificate: enrollResponse.enrollmentCert,
			rootCertificate: enrollResponse.caCertChain
		};			
		return enrollment;
    }
}
module.exports = FabricCAServices_1;