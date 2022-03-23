'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');
const ethSigUtil = require("eth-sig-util");

function uint8arrayToStringMethod(myUint8Arr){
    return String.fromCharCode.apply(null, myUint8Arr);
}

function checkSignature(nonce, signature) {
    const msgParams = {
        data: nonce,
        sig: signature
    };
    return ethSigUtil.recoverPersonalSignature(msgParams);
}

class AccessControlManager extends Contract {

    async initGovernmentOrganization(ctx){
        //this.government = [];
        //this.government.push("04cb7f10267b2b543e9065dc30694f86ed4a6a6584886004f5544af621be40dfc38adf5d76fa07ea87c34ca15171160fda4e0f14c55de55947cd860a66762f7631");
        //console.log(this.government)
        await ctx.stub.putState("governmentPubkey", Buffer.from("04d57339e6cdd71741b158eb21da6ec987364b6b9fc20d4eb19063804fe9dcdfa76041101caa4c193243d7459c59f0d59a8314666b5904bbd53f4bac20027c05e6"));
    }
    async AddPersonalAccessControl(ctx,userPubkey){
        //only org admin can add a new User key
        let org = ctx.clientIdentity.getMSPID();
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
                Attribute: [],
                Permission: {},
                AddAttribute: [],
                OrgPubkey: pubkey
            };
            accessControl.Attribute.push(org)
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
        
        //console.log(ID)
        //console.log(IDBytes)
        //console.log(uint8arrayToStringMethod(IDBytes))
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
    async AddAttributeForUser(ctx,userPubkey,attribute){
        //only governmentPubkey can add attribute.
        let pubkey = await this.GetIdentity(ctx);
        let governmentPubkey = await ctx.stub.getState("governmentPubkey");
        //console.log(this.government)
        governmentPubkey = governmentPubkey.toString();
        if(governmentPubkey == pubkey){
            let acc = await ctx.stub.getState(userPubkey);
            if(acc && acc.length){
                let accJson = JSON.parse(acc.toString())
                if(!accJson.AddAttribute.includes(attribute)){
                    accJson.AddAttribute.push(attribute);
                }
                await ctx.stub.putState(userPubkey, Buffer.from(JSON.stringify(accJson)));
                return "Add attribute Successfully."
            }
            else{
                throw new Error(`The user acc key:${userPubkey} does not exist`);
            }
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
    async PermissionOperation(ctx,reviewer,attrbutes){
        // add and remove use same function
        //only user can execute
        let attributeArray = attrbutes.split(" ");
        let pubkey = await this.GetIdentity(ctx);
        let acc = await ctx.stub.getState(pubkey);
        if(!acc || acc.length === 0){
            throw new Error(`The user acc key:${pubkey} does not exist`);
        }
        let accJson = JSON.parse(acc.toString())
        accJson.Permission[reviewer] = [];
        //check attribute exist
        attributeArray.forEach(function (attribute, index) {
            if(accJson.AddAttribute.includes(attribute)){
                accJson.Permission[reviewer].push(attribute)
            }
            else{
                throw new Error(`Attribute "${attribute}" dose not exist!`);
            }
        });
        await ctx.stub.putState(pubkey, Buffer.from(JSON.stringify(accJson)));
        return "Create PermissionOperation successfully."
    }
    async GetPermissionOperation(ctx,userPubkey){
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
        //only government can call
        let pubkey = await this.GetIdentity(ctx);
        let governmentPubkey = await ctx.stub.getState("governmentPubkey");
        
        governmentPubkey = governmentPubkey.toString();
        if(governmentPubkey == pubkey){
            let acc = await ctx.stub.getState(userPubkey);
            if(acc && acc.length){
                let accJson = JSON.parse(acc.toString())
                if(accJson.Permission[reviewer].includes(attribute)){
                    return true
                }
                else{
                    return true
                }
            }
            else{
                throw new Error(`The user acc key:${userPubkey} does not exist`);
            }
        }
        else
        {
            throw new Error(`permission denied!`);
        }
    }
}

module.exports = AccessControlManager;

