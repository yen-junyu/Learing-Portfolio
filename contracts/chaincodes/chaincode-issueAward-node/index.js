/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Contract } = require('fabric-contract-api');
const tls = require('tls');
const net = require('net');
const crypto = require("crypto");

function uint8arrayToStringMethod(myUint8Arr){
    return String.fromCharCode.apply(null, myUint8Arr);
}

class IssueAward extends Contract {
    async IssueAwardForUser(ctx, issueAddress, activityName, userPubkey, accessLink){
        
        let pubkey = await this.GetIdentity(ctx);
        let activityKey = issueAddress + activityName;
        let certManagerResponse = await ctx.stub.invokeChaincode("certManager", ["get", activityKey], "cert-channel");
        
        if(certManagerResponse.status != 200){
            throw new Error(certManagerResponse.message)
        }
        let activityInfo = JSON.parse(certManagerResponse.payload.toString());
        activityInfo = JSON.parse(activityInfo.success);
        /*
        let award = {
            student : userPubkey,
            accessLink : accessLink,
            activityName : activityName
        }
        const awardBuffer = Buffer.from(JSON.stringify(award));
        ctx.stub.setEvent('IssueAward', awardBuffer);

        let key = ctx.stub.createCompositeKey(userPubkey,[activityName])*/
        //await this.put(ctx,key,accessLink)

        //return { success: "200" };*/
        if(activityInfo.licenseAgencyPubkey == pubkey){
            //const userHash = crypto.createHash("sha256").update(userAddress).digest("hex");
            let award = {
                student : userPubkey,
                accessLink : accessLink,
                activityName : activityName
            }
            const awardBuffer = Buffer.from(JSON.stringify(award));
		    ctx.stub.setEvent('IssueAward', awardBuffer);

            let key = ctx.stub.createCompositeKey(userPubkey,[activityName])
            //console.log(key)
            //console.log(accessLink)
            await this.put(ctx,key,accessLink)

            return { success: "200" };
        }
        else
        {
            throw new Error(`permission denied`)
        }
    }
    async put(ctx, key, value) {
        await ctx.stub.putState(key, Buffer.from(value));
        return { success: "OK" };
    }
    async getAccessLink(ctx,pubkey){
        const results = await ctx.stub.getStateByPartialCompositeKeyWithPagination(
            pubkey, [], 100, undefined);
        let iterator = results.iterator;
        let result = await iterator.next();
        let accessLink = []

        while (!result.done) {
            const value = Buffer.from(result.value.value.toString()).toString('utf8');
            let keyValue = {
                key: result.value.key,
                value : value
            }
            accessLink.push(keyValue)
            result = await iterator.next();
        }
        //console.log(accessLink);
        return JSON.stringify(accessLink)
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

exports.contracts = [IssueAward];
