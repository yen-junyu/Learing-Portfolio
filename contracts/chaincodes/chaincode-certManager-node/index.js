/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');

function uint8arrayToStringMethod(myUint8Arr){
    return String.fromCharCode.apply(null, myUint8Arr);
}

class ExternalCert extends Contract { 
    async applyIssueCert(ctx, issueAddress, activityName, activityType, number){
        // only admin can add new issuer
        // add externalCert role's pubkey to chaincode
        let org = ctx.clientIdentity.getMSPID();
        let type = ctx.clientIdentity.getAttributeValue("hf.Type");
        let pubkey = await this.GetIdentity(ctx);
        /*
        if(type != "admin")
        {
            throw new Error(`only admin can execute.`);
        }*/

        let activityList = await this.get(ctx,issueAddress);
        if(activityList.success){
            activityList = JSON.parse(activityList.success.toString())
            console.log(activityList)
        }
        else{
            activityList = [];
        }
        
        if(!activityList.includes(activityName)){
            activityList.push(activityName);
            let key = issueAddress + activityName;
            let issueInfo = {
                issuerAddress: issueAddress,
                activityName : activityName,
                type : activityType,
                number: number,
                licenseAgency : org,
                licenseAgencyPubkey : pubkey,
            }
            
            await this.put(ctx, issueAddress, JSON.stringify(activityList));
            await this.put(ctx, key, JSON.stringify(issueInfo));

            return "execute applyIssueCert successfully."
        }
        else{
            throw new Error(`activityName exist.`);
        }
    }
    async getaReviewer(ctx,reviewerName,pubkey){
        const results = await ctx.stub.getStateByPartialCompositeKeyWithPagination(
            reviewerName, [], 100, undefined);
        let iterator = results.iterator;
        let result = await iterator.next();
        let reviewer = []
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let keyValue = {
                key: result.value.key,
                value : strValue
            }
            reviewer.push(keyValue)
            result = await iterator.next();
        }
        console.log(reviewer)
        return JSON.stringify(reviewer)
    
    }
    async addReviewer(ctx,reviewerName,pubkey)
    {
        
        let type = ctx.clientIdentity.getAttributeValue("hf.Type");
        /*
        if(type != "admin")
        {
            throw new Error(`only admin can execute.`);
        }*/
        //let key = ctx.stub.createCompositeKey('reviewer',[pubkey])
        let key = ctx.stub.createCompositeKey(reviewerName,[pubkey])
        await this.put(ctx, key, JSON.stringify({
            pubkey:pubkey,
            reviewerName:reviewerName
        }))
    }
    async getReviewer(ctx){
        const results = await ctx.stub.getStateByPartialCompositeKeyWithPagination(
            'reviewer', [], 100, undefined);
        let iterator = results.iterator;
        let result = await iterator.next();
        let reviewers = []
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            let keyValue = {
                key: result.value.key,
                value : strValue
            }
            reviewers.push(keyValue)
            result = await iterator.next();
        }
        //console.log(reviewers)
        return JSON.stringify(reviewers)
    }
    /*
    async applyIssueCertP(ctx, issueAddress, activityName, activityType){
        let key = ctx.stub.createCompositeKey(issueAddress,[activityName])
        await this.put(ctx, key, activityType)
        console.log(key)
    }
    async countResultsWithPagination(ctx,issueAddress){
        const pageSize = 100;
        const results = await ctx.stub.getStateByPartialCompositeKeyWithPagination(
            issueAddress, [], pageSize, undefined);
        console.log(results)
        let iterator = results.iterator;
        let result = await iterator.next();
        console.log(result);
        while (!result.done) {
            const strValue = Buffer.from(result.value.value.toString()).toString('utf8');
            console.log(result.value.key,strValue)
            result = await iterator.next();
        }
        //const count = results.metadata.fetchedRecordsCount;
        //const next = count === pageSize ? results.metadata.bookmark : undefined;
        //return {count, next};

        /*
        let allResults = [];
        let res = { done: false, value: null };
        let jsonRes = {};
        res= await ctx.stub.getStateByPartialCompositeKey(this.name, [partialKey]);
    

        while (!res.done) {
            jsonRes.Key = res.value.key;

         try {
            jsonRes.Record = JSON.parse(res.value.value.toString('utf8'));
            allResults.push(jsonRes);
            res = await iterator.next();
        }
        catch (err) {
            console.log(err);
            return {}
        }
  
}
await iterator.close();
return allResults;
    }
    */
    async put(ctx, key, value) {
        await ctx.stub.putState(key, Buffer.from(value));
        return { success: "OK" };
    }
    async get(ctx, key) {
        const buffer = await ctx.stub.getState(key);
        if (!buffer || !buffer.length) return { error: "NOT_FOUND" };
        return { success: buffer.toString() };
    }
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

exports.contracts = [ExternalCert];
