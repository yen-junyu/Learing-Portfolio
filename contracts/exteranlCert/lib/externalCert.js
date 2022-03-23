/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Contract } = require('fabric-contract-api');
const { KeyEndorsementPolicy } = require('fabric-shim');
//const { X509Certificate} = require('crypto')
const tls = require('tls');
const net = require('net');


function uint8arrayToStringMethod(myUint8Arr){
    return String.fromCharCode.apply(null, myUint8Arr);
 }

class ExternalCert extends Contract { 
    async applyIssueCert(ctx, issueAddress,activityName,activityType,number,API){
        // only admin can add new issuer
        // add externalCert role's pubkey to chaincode 
        let org = ctx.clientIdentity.getMSPID();
        let type = ctx.clientIdentity.getAttributeValue("hf.Type");
        let pubkey = await this.GetIdentity(ctx);
        console.log(pubkey)
        if(type!="admin")
        {
            throw new Error(`only admin can execute.`);
        }
        let activityList = await ctx.stub.getState(issueAddress);
        if(activityList && activityList.length > 0){
            activityList = JSON.parse(activityList.toString())
        }
        else{
            activityList = [];
        }

        if(!activityList.includes(activityName)){
            activityList.push(activityName);
            await ctx.stub.putState(issueAddress, Buffer.from(JSON.stringify(activityList)));
            console.log(activityList)
            let key = issueAddress + activityName;
            let issueInfo = {
                issuerAddress: issueAddress,
                activityName : activityName,
                type : activityType,
                number: number,
                API : API,
                licenseAgency : org,
                licenseAgencyPubkey : pubkey,
            }
            console.log(issueInfo)
            await ctx.stub.putState(key, Buffer.from(JSON.stringify(issueInfo)));
            return "applyIssueCert successfully."
        }
        else{
            throw new Error(`activityName exist.`);
        }
    }
    async GetState(ctx,key){
        let result = await ctx.stub.getState(key);
        return result.toString();
    }
    async GetAllState(ctx) {
        // for Debug
        const allResults = [];
        // range query with empty string for startKey and endKey does an open-ended query of all assets in the chaincode namespace.
        const iterator = await ctx.stub.getStateByRange('', '');
        let result = await iterator.next();
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let record;
            try {
                record = JSON.parse(strValue);
            } catch (err) {
                console.log(err);
                record = strValue;
            }
            allResults.push({ Key: result.value.key, Record: record });
            result = await iterator.next();
        }
        console.log(allResults)
        return JSON.stringify(allResults);
    }
    /*
    async SetAdminIdentity(ctx, userID, addPubkey){
        // only admin can add create external cert.
        let org = ctx.clientIdentity.getMSPID();
        let type = ctx.clientIdentity.getAttributeValue("hf.Type")
        let adminID = ctx.clientIdentity.getAttributeValue("hf.EnrollmentID")

        let key = "adminIdentity/" + org
        if(type == "admin"){
            let result = await ctx.stub.getState(key)
            if(!result || result.length==0){
                console.log("start initial.")
                let adminPubkey = await this.GetIdentity(ctx);
                let orgAdmins = {
                    pubkeys: [adminPubkey],
                    admins : [{
                        ID : adminID,
                        pubkey : adminPubkey
                    }]
                }
                let result = await ctx.stub.putState(key, Buffer.from(JSON.stringify(orgAdmins)));
                return JSON.stringify(orgAdmins)
            }
            else
            {
                console.log("add new admin")
                let orgAdmins = JSON.parse(result.toString());
                let adminPubkey = await this.GetIdentity(ctx);
                if(orgAdmins.pubkeys.includes(adminPubkey)){
                    orgAdmins.pubkeys.push(addPubkey)
                    let admin = {
                        ID : userID,
                        pubkey : addPubkey
                    }
                    orgAdmins.admins.push(admin)
                    console.log(orgAdmins)

                    let result = await ctx.stub.putState(key, Buffer.from(JSON.stringify(orgAdmins)));
                    return JSON.stringify(orgAdmins)
                }
                else{
                    console.log("adminPubkey not in orgAdmins")
                    throw new Error(`permission denied!`);
                }
            }
        }
        else{
            console.log(type)
            throw new Error(`permission denied!`);
        }
    }
    async SetAssetForUser(ctx,userID){
        let org = ctx.clientIdentity.getMSPID();
        let type = ctx.clientIdentity.getAttributeValue("hf.Type")
        let certID = ctx.clientIdentity.getAttributeValue("hf.EnrollmentID")

        console.log(certID,type)
        let userManagement = {
            userID : userID,
            org : org,
            msg : "test1",
        }
        let key = org + '/' + userID;

        if(type == "admin"){
            let result = await ctx.stub.putState(key, Buffer.from(JSON.stringify(userManagement)));
            console.log(result)
            return JSON.stringify(userManagement);
        }
        else{
            throw new Error(`permission denied!`);
        }
    }
    async ReadAsset(ctx){
        let org = ctx.clientIdentity.getMSPID();
        let userName = ctx.clientIdentity.getAttributeValue("hf.EnrollmentID")
        console.log(userName)
        let key = org + '/' + userName;
        let result = await ctx.stub.getState(key);
        if(!result || result.length === 0){
            throw new Error(`The key ${userName} does not exist`);
        }
        return result.toString();
    }
    
    async SetAssetPolicy(ctx){
        let org = ctx.clientIdentity.getMSPID();
        let userName = ctx.clientIdentity.getAttributeValue("hf.EnrollmentID")
        console.log(userName)
        let key = org + '/' + userName;
        
        //const ep = new KeyEndorsementPolicy();
        //ep.addOrgs('MEMBER', ...org);
        //await ctx.stub.setStateValidationParameter(key, ep.getPolicy());
    }*/
    async GetIdentity(ctx) {
        let IDBytes = ctx.clientIdentity.getIDBytes();
      
        let secureContext = tls.createSecureContext({
            cert: uint8arrayToStringMethod(IDBytes)
        });
        let secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
        let cert = secureSocket.getCertificate();
        let pubkey = cert.pubkey.toString('hex');
        
        return pubkey
    }
}
module.exports = ExternalCert;
