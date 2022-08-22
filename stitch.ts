const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require("crypto"); 
import fetch from 'node-fetch';
import * as functions from 'firebase-functions';

const pemCert = functions.config().stitch.production.pemcertificate;
const clientId = functions.config().stitch.production.clientid;
const clientSecret = functions.config().stitch.production.clientsecret;
// const pemCert = functions.config().stitch.test.pemcertificate;
// const clientId = functions.config().stitch.test.clientid;
// const clientSecret = functions.config().stitch.test.clientsecret;


// Get JWT token
/******************************************************************************************************** */
function getToken(){
    function getKeyId(cert: string) {
        const lines = cert.split('\n').filter(x => x.includes('localKeyID:'))[0];
        const result = lines.replace('localKeyID:', '').replace(/\W/g, '');
        return result;
    }

    const issuer = clientId;
    const subject = clientId;
    const audience = 'https://secure.stitch.money/connect/token';
    const keyid = getKeyId(pemCert);
    const jwtid = crypto.randomBytes(16).toString("hex");
    const options = {
        keyid,
        jwtid,
        notBefore: "0",
        issuer,
        subject,
        audience,
        expiresIn: "5m", // For this example this value is set to 5 minutes, but for machine usage should generally be a lot shorter 
        algorithm: "RS256"
    };

    const token = jwt.sign({}, pemCert, options);
    return token;
}

// Fetch access token
/******************************************************************************************************** */
// async function retrieveTokenUsingAuthorizationCode(clientId: string, clientSecret: string) {
async function retrieveTokenUsingAuthorizationCode(jwtToken: string) {
    const body = {
        grant_type: 'client_credentials',
        client_id: clientId,        
        client_secret: clientSecret,        
        scope: 'client_paymentrequest',
        audience: 'https://secure.stitch.money/connect/token',
        client_assertion: jwtToken,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    };
    const bodyString = Object.entries(body).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
    const response = await fetch('https://secure.stitch.money/connect/token', {
        method: 'post',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: bodyString,
    });
    const responseBody = await response.json();
    return responseBody;
}

// Fetch call to create single payment request
// Left in so that you have an example of making a graphql request (although I think that there are NPM 
// packages that make this easier than how I've done it here)
/******************************************************************************************************** */
async function CreateSinglePaymentRequest(accessToken: string, 
    amount: string, 
    payerReference: string, 
    beneficiaryReference: string, 
    beneficiaryName: string, 
    beneficiaryBankId: string, 
    beneficiaryAccountNumber: string, ) {

    // GraphQL query
    const query = 
        `mutation CreatePaymentRequest(
            $amount: MoneyInput!, 
            $payerReference: String!, 
            $beneficiaryReference: String!, 
            $beneficiaryName: String!, 
            $beneficiaryBankId: BankBeneficiaryBankId!, 
            $beneficiaryAccountNumber: String!) { 
        clientPaymentInitiationRequestCreate(input: {
            amount: $amount, 
            payerReference: $payerReference, 
            beneficiaryReference: $beneficiaryReference, 
            beneficiary : {
                bankAccount: {
                    name: $beneficiaryName, 
                    bankId: $beneficiaryBankId, 
                    accountNumber: $beneficiaryAccountNumber 
                }
            }
        }) {
        paymentInitiationRequest {
            id
            url
        }
        }
    }`

    // GraphQL variables
    const variables =             
        {
            amount: { 
                currency: "ZAR", quantity: amount 
            }, 
            payerReference: payerReference, 
            beneficiaryReference: beneficiaryReference, 
            beneficiaryName: beneficiaryName, 
            beneficiaryBankId: beneficiaryBankId, 
            beneficiaryAccountNumber: beneficiaryAccountNumber
        }

    // Fetch call
    let response = await fetch('https://api.stitch.money/graphql', {
        'method': 'POST',
        'headers': {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        'body': JSON.stringify({query, variables}),
    });   
    return response;
}

// Create payment request (has to get the relevant tokens first) (for use when depositing into Moola bank 
// account)
// Left this here so that you have an example of how to use the auth flow and make a request
/******************************************************************************************************** */
export async function createPaymentRequestDeposit(amount: string, payerReference: string, beneficiaryReference: string){
    try {
        let jwttoken = getToken();
        let authtoken = await retrieveTokenUsingAuthorizationCode(jwttoken);
        let paymentRequest = await CreateSinglePaymentRequest(authtoken['access_token'], 
            amount, 
            payerReference, 
            beneficiaryReference, 
            'Moola', 
            'fnb', 
            '62881050349')
        let paymentRequestJSON = await paymentRequest.json()
        return paymentRequestJSON;
    } catch(error) {
        console.error('ERROR!', error);
        throw error;
    }
    
}
