'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');
//const ethSigUtil = require("eth-sig-util");

function uint8arrayToStringMethod(myUint8Arr){
    return String.fromCharCode.apply(null, myUint8Arr);
}

/*
function checkSignature(nonce, signature) {
    const msgParams = {
        data: nonce,
        sig: signature
    };
    return ethSigUtil.recoverPersonalSignature(msgParams);
}*/

class AccessControlManager extends Contract {
    async AddPersonalAccessControl(ctx, userPubkey){
        //only org admin can add a new User key
        let org = ctx.clientIdentity.getMSPID().replace('MSP','')
        let type = ctx.clientIdentity.getAttributeValue("hf.Type");
        let acc = await ctx.stub.getState(userPubkey);
        let pubkey = await this.GetIdentity(ctx);
        
        if(type!="admin"){
            throw new Error(`only admin can execute.`);
        }      
        if(acc && acc.length > 0){
            throw new Error(`User already exists`);
        }
        else
        {
            let accessControl = 
            {
                Attribute: [],  // only user can change
                Permission: {}, // only user can change
                AddAttribute: [], // only the same OrgPubkey can be changed 
                OrgPubkey: pubkey // user belongs to the organization
            };

            accessControl.Attribute.push(org + "SchoolGrade")
            //await ctx.stub.putState(hashUserAddress,Buffer.from(userPubkey))
            await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(accessControl)));
            return "Create Successfully."
        }
    }
    async GetUserAccControl(ctx,key){
        //Only the organization that created the acc can read
        let pubkey = await this.GetIdentity(ctx);
        const acc = await ctx.stub.getState(key);
        
        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${key} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        if(accJson.OrgPubkey!=pubkey){
            throw new Error(`permission denied!`);
        }

        return acc.toString();
    }
    async UserAccControlExist(ctx, key) {
        const acc = await ctx.stub.getState(key);
        return acc && acc.length > 0;
    }
    async GetIdentity(ctx) {
        let org = ctx.clientIdentity.getMSPID();
        let ID = ctx.clientIdentity.getID();
        let IDBytes = ctx.clientIdentity.getIDBytes();
        
        let secureContext = tls.createSecureContext({
            cert: uint8arrayToStringMethod(IDBytes)
        });
        let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
        let cert = secureSocket.getCertificate();
        //console.log(cert)
        let pubkey = cert.pubkey.toString('hex');
        
        return pubkey
    }
    async Deletekey(ctx, key) {
        const exists = await this.UserAccControlExist(ctx, key);
        if (!exists) {
            throw new Error(`The key ${key} does not exist`);
        }
        return ctx.stub.deleteState(key);
    }
    async AddAttributeForUser(ctx, userPubkey, attribute){
        let type = ctx.clientIdentity.getAttributeValue("hf.Type");
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(userPubkey);

        
        let accJson;
        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${key} does not exist`);
        }
        else{
            accJson = JSON.parse(acc.toString())
        }
        
        if(accJson.OrgPubkey != pubkey){
            throw new Error(`permission denied!`);
        }

        if(type == "admin"){
            if(!accJson.AddAttribute.includes(attribute)){
                accJson.AddAttribute.push(attribute);
            }
            console.log(accJson)
            await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(accJson)));
            return "Add attribute Successfully."
        }
        else
        {
            throw new Error(`permission denied!`);
        }
    }
    async AddAttribute(ctx,attribute){
        //only user can execute
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(pubkey);
        
        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${pubkey} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        if(accJson.AddAttribute.includes(attribute)){
            accJson.AddAttribute = accJson.AddAttribute.filter(item => item !== attribute)
            accJson.Attribute.push(attribute)
            await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
            return "AddAttribute successfully."
        }
        else{
            throw new Error(`Attribute "${attribute}" dose not exist!`);
        }
    }
    async UpatePermission(ctx,reviewer,attrbutes){
        // only user can execute
        let attributeArray = attrbutes.split("|");
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(pubkey);

        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${pubkey} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        
        accJson.Permission[reviewer] = [];
        //check attribute exist
        attributeArray.forEach(function (attribute, index) {
            if(accJson.Attribute.includes(attribute)){
                accJson.Permission[reviewer].push(attribute)
            }
            else{
                throw new Error(`Attribute "${attribute}" dose not exist!`);
            }
        });
        await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
        return "Upate Permission successfully."
    }
    async RevokePermission(ctx,reviewer){
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(pubkey);

        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${pubkey} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        let permission =  accJson.Permission;
        console.log(permission)
        delete permission[reviewer];
        console.log(permission)
        console.log(accJson)
        await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
        return "Revoke Permission successfully."
    }
    async GetPermission(ctx,userPubkey){
        // reviewer get user permission
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(userPubkey);
        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${pubkey} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        if(accJson.Permission[pubkey]){
            return JSON.stringify(accJson.Permission[pubkey])
        }
        else{
            throw new Error(`permission denied!`);
        }
    }
    async ConfirmUserAuthorization(ctx,userPubkey,reviewer,attribute){
        let acc = await ctx.stub.getState(userPubkey);
        if(acc && acc.length){
            let accJson = JSON.parse(acc.toString())
            if(accJson.Permission[reviewer].includes(attribute)){
                return true
            }
            else{
                return false
            }
        }
        else{
            throw new Error(`The user acc key:${userPubkey} does not exist`);
        }
    }
}
exports.contracts = [AccessControlManager];

