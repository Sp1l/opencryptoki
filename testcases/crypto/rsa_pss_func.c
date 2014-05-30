#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "common.c"
#include "regress.h"

#include "rsa_pss.h"

CK_RV do_SignRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
        int                     i;
        CK_BYTE                 message[MAX_MESSAGE_SIZE];
        CK_BYTE                 actual[MAX_SIGNATURE_SIZE];
        CK_BYTE                 expected[MAX_SIGNATURE_SIZE];
        CK_ULONG                message_len, actual_len, expected_len;
	CK_BYTE			salt[20];

        CK_MECHANISM            mech;
        CK_OBJECT_HANDLE        priv_key;

        CK_SLOT_ID              slot_id = SLOT_ID;
        CK_SESSION_HANDLE       session;
        CK_FLAGS                flags;
        CK_BYTE                 user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG                user_pin_len;
        CK_RV                   rc, loc_rc;
	CK_RSA_PKCS_PSS_PARAMS pss_params;

	CK_BYTE hash[20];
	CK_ULONG h_len = 20;

        // begin testsuite
        testsuite_begin("%s Sign. ", tsuite->name);
        testcase_rw_session();
        testcase_user_login();

        // skip tests if the slot doesn't support this mechanism **/
        if (! mech_supported(slot_id, tsuite->mech.mechanism)){
                testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }


        // iterate over test vectors
        for (i = 0; i < tsuite->tvcount; i++){
                testcase_begin("%s Sign with test vector %d.",
                                tsuite->name, i);

                rc = CKR_OK; // set return value

                // clear buffers
                memset(message, 0, MAX_MESSAGE_SIZE);
                memset(actual, 0, MAX_SIGNATURE_SIZE);
                memset(expected, 0, MAX_SIGNATURE_SIZE);
		memset(salt, 0, 20);

                actual_len = MAX_SIGNATURE_SIZE; // set buffer size

                // get message
                message_len = tsuite->tv[i].msg_len;
                memcpy(message, tsuite->tv[i].msg, message_len);

                // get (expected) signature
                expected_len = tsuite->tv[i].sig_len;
                memcpy(expected, tsuite->tv[i].sig, expected_len);
	
                // create (private) key handle
                rc = create_RSAPrivateKey(session,
                                        tsuite->tv[i].mod,
                                        tsuite->tv[i].pub_exp,
                                        tsuite->tv[i].priv_exp,
                                        tsuite->tv[i].prime1,
                                        tsuite->tv[i].prime2,
                                        tsuite->tv[i].exp1,
                                        tsuite->tv[i].exp2,
                                        tsuite->tv[i].coef,
                                        tsuite->tv[i].mod_len,
                                        tsuite->tv[i].pubexp_len,
                                        tsuite->tv[i].privexp_len,
                                        tsuite->tv[i].prime1_len,
                                        tsuite->tv[i].prime2_len,
                                        tsuite->tv[i].exp1_len,
                                        tsuite->tv[i].exp2_len,
                                        tsuite->tv[i].coef_len,
                                        &priv_key);
                if (rc != CKR_OK) {
                        testcase_error("create_RSAPrivateKey(), rc=%s",
                                p11_get_ckr(rc));
                        goto error;
                }

		/* first create hash of message */
		mech.mechanism = CKM_SHA_1;
		mech.pParameter = 0;
		mech.ulParameterLen = 0;
		
		rc = funcs->C_DigestInit(session, &mech);
		if (rc != CKR_OK) {
                        testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
		rc = funcs->C_Digest(session,message,message_len,hash,&h_len);
                if (rc != CKR_OK) {
                        testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }

                // set mechanism for signing
                mech = tsuite->mech;
		pss_params.hashAlg = CKM_SHA_1;
		pss_params.mgf = CKG_MGF1_SHA1;
		pss_params.sLen = tsuite->tv[i].salt_len;
		memcpy(salt, tsuite->tv[i].salt, 20);
		pss_params.salt = salt;

		mech.pParameter = &pss_params;
		mech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

                // initialize signing
                rc = funcs->C_SignInit(session, &mech, priv_key);
                if (rc != CKR_OK) {
                        testcase_error("C_SignInit(), rc=%s.", p11_get_ckr(rc));
                        goto error;
                }

                // do signing
                rc = funcs->C_Sign(session, hash, h_len, actual, &actual_len);
                if (rc != CKR_OK) {
                        testcase_error("C_Sign(), rc=%s.", p11_get_ckr(rc));
                        goto error;
                }

                // check results
                testcase_new_assertion();

                if (actual_len != expected_len) {
                        testcase_fail("%s Sign with test vector %d failed. "
                                "Expected len=%ld, found len=%ld.",
                                tsuite->name, i, expected_len, actual_len);
                }

                else if (memcmp(actual, expected, expected_len)) {
                        testcase_fail("%s Sign with test vector %d failed. "
                                "Signature data does not match test vector "
                                "signature.", tsuite->name, i);

                }

                else {
                        testcase_pass("C_Sign.");
                }
error:
                // clean up
                rc = funcs->C_DestroyObject(session, priv_key);
                if (rc != CKR_OK) {
                        testcase_error("C_DestroyObject(), rc=%s.",
                                p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

testcase_cleanup:
        testcase_user_logout();
        loc_rc = funcs->C_CloseAllSessions(slot_id);
        if (loc_rc != CKR_OK) {
                testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(rc));
        }
        return rc;
}

CK_RV do_VerifyRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
        int                     i;
        CK_BYTE                 actual[MAX_SIGNATURE_SIZE];
        CK_BYTE                 message[MAX_MESSAGE_SIZE];
        CK_ULONG                message_len;
        CK_BYTE                 signature[MAX_SIGNATURE_SIZE];
        CK_ULONG                signature_len;

        CK_MECHANISM            mech;
        CK_OBJECT_HANDLE        publ_key;

        CK_SLOT_ID              slot_id = SLOT_ID;
        CK_SESSION_HANDLE       session;
        CK_FLAGS                flags;
        CK_BYTE                 user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG                user_pin_len;
        CK_RV                   rc, loc_rc;
	CK_RSA_PKCS_PSS_PARAMS pss_params;

	CK_BYTE hash[20];
	CK_ULONG h_len = 20;

        // begin testsuite
        testsuite_begin("%s Verify.", tsuite->name);
        testcase_rw_session();
        testcase_user_login();

        // skip tests if the slot doesn't support this mechanism
        if (! mech_supported(slot_id, tsuite->mech.mechanism)){
                testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism );
                goto testcase_cleanup;
        }

        // iterate over test vectors
        for (i = 0; i < tsuite->tvcount; i++){

                testcase_begin("%s Verify with test vector %d.",
                                tsuite->name, i);

                rc = CKR_OK; // set return value

                // clear buffers
                memset(message, 0, MAX_MESSAGE_SIZE);
                memset(signature, 0, MAX_SIGNATURE_SIZE);
                memset(actual, 0, MAX_SIGNATURE_SIZE);

                // get message
                message_len = tsuite->tv[i].msg_len;
                memcpy(message, tsuite->tv[i].msg, message_len);

                // get signature
                signature_len = tsuite->tv[i].sig_len;
                memcpy(signature, tsuite->tv[i].sig, signature_len);

                // create (public) key handle
                rc = create_RSAPublicKey(session,
                                tsuite->tv[i].mod,
                                tsuite->tv[i].pub_exp,
                                tsuite->tv[i].mod_len,
                                tsuite->tv[i].pubexp_len,
                                &publ_key);

                if (rc != CKR_OK) {
                        testcase_error("create_RSAPublicKey(), rc=%s",
                                p11_get_ckr(rc));
                        goto error;
                }

		/* first create hash of message */
		mech.mechanism = CKM_SHA_1;
		mech.pParameter = 0;
		mech.ulParameterLen = 0;
		
		rc = funcs->C_DigestInit(session, &mech);
		if (rc != CKR_OK) {
                        testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
		rc = funcs->C_Digest(session,message,message_len,hash,&h_len);
                if (rc != CKR_OK) {
                        testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }

                // set mechanism
                mech = tsuite->mech;
		pss_params.hashAlg = CKM_SHA_1;
		pss_params.mgf = CKG_MGF1_SHA1;
		pss_params.sLen = tsuite->tv[i].salt_len;

		mech.pParameter = &pss_params;
		mech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

                // initialize verify
                rc = funcs->C_VerifyInit(session, &mech, publ_key);
                if (rc != CKR_OK) {
                        testcase_error("C_VerifyInit(), rc=%s",
                                p11_get_ckr(rc));
                        goto error;
                }

                // do verify
                rc = funcs->C_Verify(session, hash, h_len, signature,
					signature_len);

                // check result
                testcase_new_assertion();

                if (rc == CKR_OK){
                        testcase_pass("C_Verify.");
                }

                else {
                        testcase_fail("%s Sign Verify with test vector %d "
                                "failed.", tsuite->name, i);
                }

error:
                // clean up
                rc = funcs->C_DestroyObject(session, publ_key);
                if (rc != CKR_OK) {
                        testcase_error("C_DestroyObject(), rc=%s.",
                                p11_get_ckr(rc));
                        goto testcase_cleanup;
                }

        }

testcase_cleanup:
        testcase_user_logout();
       loc_rc = funcs->C_CloseAllSessions(slot_id);
        if (loc_rc != CKR_OK) {
                testcase_error("C_CloseAllSessions loc_rc=%s", p11_get_ckr(loc_rc));
        }
        return rc;
}

CK_RV rsa_funcs()
{
        int     i;
        CK_RV   rv = CKR_OK;

        // published (known answer) tests
        for (i = 0; i < NUM_OF_PUBLISHED_PSS_TESTSUITES; i++) {
                rv = do_SignRSA(&pss_published_test_suites[i]);
                if (rv != CKR_OK && (!no_stop))
                        break;
        }

        for (i = 0; i < NUM_OF_PUBLISHED_PSS_TESTSUITES; i++) {
                rv = do_VerifyRSA(&pss_published_test_suites[i]);
                if (rv != CKR_OK && (!no_stop))
                        break;
        }

        return rv;
}

int main  (int argc, char **argv){
        int rc;
        CK_C_INITIALIZE_ARGS cinit_args;
        CK_RV rv;

        rc = do_ParseArgs(argc, argv);
        if(rc != 1){
                return rc;
        }

        printf("Using slot #%lu...\n\n", SLOT_ID);
        printf("With option: no_stop: %d\n", no_stop);

        rc = do_GetFunctionList();
        if(! rc) {
                PRINT_ERR("ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
                return rc;
        }

        memset( &cinit_args, 0x0, sizeof(cinit_args) );
        cinit_args.flags = CKF_OS_LOCKING_OK;

        funcs->C_Initialize( &cinit_args );
        {
                CK_SESSION_HANDLE hsess = 0;
                rc = funcs->C_GetFunctionStatus(hsess);
                if (rc != CKR_FUNCTION_NOT_PARALLEL){
                    return rc;
                }

                rc = funcs->C_CancelFunction(hsess);
                if (rc != CKR_FUNCTION_NOT_PARALLEL){
                    return rc;
                }
        }

        testcase_setup(0);
        rv = rsa_funcs();
        testcase_print_result();
        return rv;
}
