/*
 * DroidRaksha YARA Rules — India-Specific Threat Patterns (Round 2)
 * Expanded from 6 → 23 rules covering:
 * Fake Aadhaar, IRCTC, CoWIN, TRAI, Income Tax, ED impersonators,
 * loan sharks, fake mutual funds, WhatsApp OTP stealers,
 * GST fraud, EPFO scams, fake RBI/CBI apps, DigiLocker phishing
 * Author: DroidRaksha / PHAPGUYZ Team
 */

/* ================================================================
   EXISTING RULES (R1) — Preserved
   ================================================================ */

rule Fake_UPI_App
{
    meta:
        description = "Detects fake UPI payment apps targeting Indian users"
        severity = "CRITICAL"
        tags = "upi, india, fraud, financial"
    strings:
        $upi1 = "upi" ascii wide nocase
        $upi2 = "BHIM" ascii wide
        $upi3 = "PhonePe" ascii wide nocase
        $upi4 = "Google Pay" ascii wide nocase
        $upi5 = "Paytm" ascii wide nocase
        $cert1 = "phonepe" ascii wide nocase
        $cert2 = "npci" ascii wide nocase
        $malicious1 = "interceptTransaction" ascii wide nocase
        $malicious2 = "captureUPI" ascii wide nocase
        $malicious3 = "upi_pin" ascii wide nocase
        $malicious4 = "mpin" ascii wide nocase
    condition:
        any of ($upi*) and any of ($malicious*) or $cert1 or $cert2
}

rule Loan_Scam_App
{
    meta:
        description = "Detects predatory loan scam apps that harvest contacts and photos"
        severity = "HIGH"
        tags = "loan, scam, india, financial"
    strings:
        $loan1 = "instant loan" ascii wide nocase
        $loan2 = "quick cash" ascii wide nocase
        $loan3 = "loan approved" ascii wide nocase
        $loan4 = "no documents" ascii wide nocase
        $loan5 = "aadhar loan" ascii wide nocase
        $loan6 = "pan loan" ascii wide nocase
        $contact1 = "READ_CONTACTS" ascii wide
        $contact2 = "uploadContactList" ascii wide nocase
        $camera1 = "CAMERA" ascii wide
        $storage1 = "READ_EXTERNAL_STORAGE" ascii wide
    condition:
        any of ($loan*) and ($contact1 or $contact2) and ($camera1 or $storage1)
}

rule Aadhaar_Harvester
{
    meta:
        description = "Detects apps harvesting Aadhaar ID numbers"
        severity = "CRITICAL"
        tags = "aadhaar, identity_theft, india"
    strings:
        $re1 = /[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}/ ascii wide
        $re2 = /aadhaar/i ascii wide
        $re3 = /aadhar/i ascii wide
        $api1 = "uidai" ascii wide nocase
        $api2 = "aadhaar_number" ascii wide nocase
        $api3 = "aadhar_card" ascii wide nocase
        $ocr1 = "OCR" ascii wide
        $ocr2 = "TextRecognizer" ascii wide
        $ocr3 = "MLKitOCR" ascii wide
    condition:
        (any of ($re*) or any of ($api*)) and any of ($ocr*)
}

rule Fake_Bank_App
{
    meta:
        description = "Detects apps impersonating Indian banks (SBI, HDFC, ICICI, etc.)"
        severity = "CRITICAL"
        tags = "banking, phishing, india"
    strings:
        $bank1 = "sbi" ascii wide nocase
        $bank2 = "hdfc" ascii wide nocase
        $bank3 = "icici" ascii wide nocase
        $bank4 = "axis bank" ascii wide nocase
        $bank5 = "kotak" ascii wide nocase
        $bank6 = "yesbank" ascii wide nocase
        $bank7 = "pnb" ascii wide nocase
        $bank8 = "canara" ascii wide nocase
        $phish1 = "netbanking" ascii wide nocase
        $phish2 = "internet banking" ascii wide nocase
        $steal1 = "captureNetBanking" ascii wide nocase
        $steal2 = "bank_credentials" ascii wide nocase
        $steal3 = "account_number" ascii wide nocase
        $overlay = "SYSTEM_ALERT_WINDOW" ascii wide
    condition:
        any of ($bank*) and ($overlay or any of ($phish*) or any of ($steal*))
}

rule OTP_Stealer
{
    meta:
        description = "Detects OTP stealing targeting Indian banking and UPI"
        severity = "CRITICAL"
        tags = "otp, banking, india, sms"
    strings:
        $otp1 = "OTP" ascii wide
        $otp2 = "One Time Password" ascii wide nocase
        $otp3 = "verification code" ascii wide nocase
        $sms1 = "RECEIVE_SMS" ascii wide
        $sms2 = "SmsMessage" ascii wide
        $sms3 = "getMessageBody" ascii wide
        $forward1 = "forwardSMS" ascii wide nocase
        $forward2 = "sendSMSToServer" ascii wide nocase
        $forward3 = "uploadSMS" ascii wide nocase
        $bank_ref1 = "NEFT" ascii wide
        $bank_ref2 = "RTGS" ascii wide
        $bank_ref3 = "IMPS" ascii wide
    condition:
        any of ($otp*) and $sms1 and ($sms2 or $sms3) and
        (any of ($forward*) or any of ($bank_ref*))
}

rule PAN_Card_Harvester
{
    meta:
        description = "Detects harvesting of PAN card numbers"
        severity = "HIGH"
        tags = "pan, identity_theft, india"
    strings:
        $pan_regex = /[A-Z]{5}[0-9]{4}[A-Z]{1}/ ascii wide
        $pan1 = "pan_number" ascii wide nocase
        $pan2 = "pan_card" ascii wide nocase
        $pan3 = "permanent account number" ascii wide nocase
        $ocr1 = "OCR" ascii wide
        $ocr2 = "TextRecognizer" ascii wide
    condition:
        ($pan_regex or any of ($pan*)) and any of ($ocr*)
}

/* ================================================================
   NEW RULES — Round 2 (17 New India-Specific Rules)
   ================================================================ */

rule Fake_IRCTC_App
{
    meta:
        description = "Detects apps impersonating IRCTC (Indian Railways ticket booking) for phishing"
        severity = "CRITICAL"
        tags = "irctc, railways, india, phishing"
    strings:
        $irctc1 = "irctc" ascii wide nocase
        $irctc2 = "Indian Railways" ascii wide nocase
        $irctc3 = "IRCTC Connect" ascii wide nocase
        $irctc4 = "Rail Connect" ascii wide nocase
        $phish1 = "irctc_password" ascii wide nocase
        $phish2 = "captureIRCTC" ascii wide nocase
        $phish3 = "userID" ascii wide nocase
        $steal1 = "SYSTEM_ALERT_WINDOW" ascii wide
        $steal2 = "AccessibilityService" ascii wide
    condition:
        any of ($irctc*) and (any of ($phish*) or any of ($steal*))
}

rule Fake_CoWIN_Aarogya
{
    meta:
        description = "Detects fake CoWIN / Aarogya Setu vaccination certificate apps"
        severity = "CRITICAL"
        tags = "cowin, aarogya_setu, india, phishing, health"
    strings:
        $cow1 = "cowin" ascii wide nocase
        $cow2 = "CoWIN" ascii wide
        $cow3 = "aarogya" ascii wide nocase
        $cow4 = "aarogyasetu" ascii wide nocase
        $cow5 = "vaccination certificate" ascii wide nocase
        $cow6 = "beneficiary" ascii wide nocase
        $steal1 = "aadhaar" ascii wide nocase
        $steal2 = "phone_number" ascii wide nocase
        $steal3 = "mobile_otp" ascii wide nocase
        $upload1 = "uploadProfile" ascii wide nocase
        $upload2 = "health_data" ascii wide nocase
    condition:
        any of ($cow*) and (any of ($steal*) or any of ($upload*))
}

rule Fake_TRAI_DoT_App
{
    meta:
        description = "Detects TRAI/DoT impersonator apps used in 'digital arrest' scams"
        severity = "CRITICAL"
        tags = "trai, dot, india, digital_arrest, scam"
    strings:
        $t1 = "TRAI" ascii wide
        $t2 = "Department of Telecommunications" ascii wide nocase
        $t3 = "DoT" ascii wide
        $t4 = "SIM blocked" ascii wide nocase
        $t5 = "TRAI notice" ascii wide nocase
        $t6 = "telecom regulator" ascii wide nocase
        $scam1 = "your number will be disconnected" ascii wide nocase
        $scam2 = "illegal activities" ascii wide nocase
        $scam3 = "cybercrime" ascii wide nocase
        $call1 = "CALL_PHONE" ascii wide
        $mic1 = "RECORD_AUDIO" ascii wide
    condition:
        any of ($t*) and (any of ($scam*) and ($call1 or $mic1))
}

rule Fake_Income_Tax_IT_App
{
    meta:
        description = "Detects fake Income Tax Department apps — used in refund fraud"
        severity = "CRITICAL"
        tags = "income_tax, it_dept, india, refund_fraud"
    strings:
        $it1 = "incometax.gov.in" ascii wide nocase
        $it2 = "Income Tax Department" ascii wide nocase
        $it3 = "IT Refund" ascii wide nocase
        $it4 = "e-filing" ascii wide nocase
        $it5 = "Form 26AS" ascii wide nocase
        $it6 = "TDS refund" ascii wide nocase
        $steal1 = "pan_number" ascii wide nocase
        $steal2 = "aadhaar_number" ascii wide nocase
        $steal3 = "bank_account" ascii wide nocase
        $steal4 = "ifsc" ascii wide nocase
    condition:
        any of ($it*) and 2 of ($steal*)
}

rule Fake_ED_CBI_App
{
    meta:
        description = "Detects ED/CBI/Police impersonator apps used in digital extortion 'digital arrest' scam"
        severity = "CRITICAL"
        tags = "ed, cbi, police, digital_arrest, india, extortion"
    strings:
        $law1 = "Enforcement Directorate" ascii wide nocase
        $law2 = "Central Bureau of Investigation" ascii wide nocase
        $law3 = "CBI" ascii wide
        $law4 = "Cyber Crime Cell" ascii wide nocase
        $law5 = "Mumbai Police" ascii wide nocase
        $law6 = "cybercrime.gov.in" ascii wide nocase
        $law7 = "arrest warrant" ascii wide nocase
        $law8 = "money laundering" ascii wide nocase
        $extort1 = "pay fine" ascii wide nocase
        $extort2 = "clear your name" ascii wide nocase
        $extort3 = "settlement" ascii wide nocase
        $video1 = "VideoCall" ascii wide nocase
        $video2 = "WebRTC" ascii wide
    condition:
        any of ($law*) and (any of ($extort*) or any of ($video*))
}

rule Predatory_Loan_Shark
{
    meta:
        description = "Detects predatory instant loan shark apps with blackmail potential"
        severity = "HIGH"
        tags = "loan_shark, india, predatory, blackmail"
    strings:
        $app1 = "instant approval" ascii wide nocase
        $app2 = "loan in 5 minutes" ascii wide nocase
        $app3 = "no CIBIL" ascii wide nocase
        $app4 = "cibil score" ascii wide nocase
        $app5 = "zero interest" ascii wide nocase
        $app6 = "interest rate" ascii wide nocase
        $perm1 = "READ_CONTACTS" ascii wide
        $perm2 = "READ_EXTERNAL_STORAGE" ascii wide
        $perm3 = "CAMERA" ascii wide
        $perm4 = "READ_CALL_LOG" ascii wide
        $perm5 = "ACCESS_FINE_LOCATION" ascii wide
        $blackmail1 = "contactsBlacklist" ascii wide nocase
        $blackmail2 = "sendToContacts" ascii wide nocase
        $blackmail3 = "notifyContacts" ascii wide nocase
    condition:
        any of ($app*) and 3 of ($perm*) and any of ($blackmail*)
}

rule Fake_Mutual_Fund_Investment
{
    meta:
        description = "Detects fake mutual fund / stock investment scam apps"
        severity = "HIGH"
        tags = "mutual_fund, investment_fraud, india, sebi"
    strings:
        $inv1 = "Zerodha" ascii wide nocase
        $inv2 = "Groww" ascii wide nocase
        $inv3 = "Angel One" ascii wide nocase
        $inv4 = "Upstox" ascii wide nocase
        $inv5 = "mutual fund" ascii wide nocase
        $inv6 = "SIP" ascii wide
        $inv7 = "SEBI registered" ascii wide nocase
        $fraud1 = "guaranteed return" ascii wide nocase
        $fraud2 = "100% profit" ascii wide nocase
        $fraud3 = "risk free" ascii wide nocase
        $fraud4 = "fixed return" ascii wide nocase
        $steal1 = "demat_account" ascii wide nocase
        $steal2 = "trading_password" ascii wide nocase
    condition:
        any of ($inv*) and (any of ($fraud*) or any of ($steal*))
}

rule WhatsApp_OTP_Stealer
{
    meta:
        description = "Detects apps targeting WhatsApp OTP verification to hijack accounts"
        severity = "CRITICAL"
        tags = "whatsapp, otp, account_takeover, india"
    strings:
        $wa1 = "wa.me" ascii wide
        $wa2 = "WhatsApp" ascii wide
        $wa3 = "com.whatsapp" ascii wide
        $wa4 = "verify your number" ascii wide nocase
        $otp1 = "RECEIVE_SMS" ascii wide
        $otp2 = "getMessageBody" ascii wide
        $otp3 = "6-digit" ascii wide nocase
        $otp4 = "verification code" ascii wide nocase
        $forward1 = "forwardSMS" ascii wide nocase
        $forward2 = "api.telegram.org" ascii wide
        $forward3 = "uploadOTP" ascii wide nocase
    condition:
        any of ($wa*) and any of ($otp*) and any of ($forward*)
}

rule GST_GSTIN_Fraud
{
    meta:
        description = "Detects fake GST / GSTIN verification apps used for tax fraud"
        severity = "HIGH"
        tags = "gst, gstin, india, tax_fraud"
    strings:
        $gst1 = "gstin" ascii wide nocase
        $gst2 = "gst.gov.in" ascii wide nocase
        $gst3 = "goods and services tax" ascii wide nocase
        $gst4 = "gst refund" ascii wide nocase
        $gst5 = "input tax credit" ascii wide nocase
        $steal1 = "gstin_number" ascii wide nocase
        $steal2 = "business_pan" ascii wide nocase
        $steal3 = "turnover" ascii wide nocase
        $phish1 = "AccessibilityService" ascii wide
        $phish2 = "SYSTEM_ALERT_WINDOW" ascii wide
    condition:
        any of ($gst*) and (any of ($steal*) or any of ($phish*))
}

rule EPFO_PF_Scam
{
    meta:
        description = "Detects fake EPFO / Provident Fund withdrawal scam apps"
        severity = "HIGH"
        tags = "epfo, pf, india, retirement_fraud"
    strings:
        $epfo1 = "epfo" ascii wide nocase
        $epfo2 = "provident fund" ascii wide nocase
        $epfo3 = "PF withdrawal" ascii wide nocase
        $epfo4 = "UAN" ascii wide
        $epfo5 = "EPFO member" ascii wide nocase
        $steal1 = "uan_number" ascii wide nocase
        $steal2 = "pf_balance" ascii wide nocase
        $steal3 = "bank_ifsc" ascii wide nocase
        $steal4 = "aadhaar_seeding" ascii wide nocase
    condition:
        any of ($epfo*) and 2 of ($steal*)
}

rule Fake_DigiLocker
{
    meta:
        description = "Detects apps impersonating DigiLocker to harvest government credentials"
        severity = "CRITICAL"
        tags = "digilocker, india, government, credential_theft"
    strings:
        $dl1 = "digilocker" ascii wide nocase
        $dl2 = "DigiLocker" ascii wide
        $dl3 = "digitallocker.gov.in" ascii wide nocase
        $dl4 = "government documents" ascii wide nocase
        $dl5 = "driving licence" ascii wide nocase
        $dl6 = "vehicle registration" ascii wide nocase
        $steal1 = "aadhaar" ascii wide nocase
        $steal2 = "digi_password" ascii wide nocase
        $steal3 = "captureDocument" ascii wide nocase
        $overlay = "SYSTEM_ALERT_WINDOW" ascii wide
    condition:
        any of ($dl*) and (any of ($steal*) or $overlay)
}

rule RBI_Payment_Scam
{
    meta:
        description = "Detects fake RBI / payment gateway apps for refund or KYC scams"
        severity = "CRITICAL"
        tags = "rbi, india, payment, kyc_fraud"
    strings:
        $rbi1 = "Reserve Bank of India" ascii wide nocase
        $rbi2 = "rbi.org.in" ascii wide nocase
        $rbi3 = "RBI" ascii wide
        $rbi4 = "RBI Approved" ascii wide nocase
        $kyc1 = "KYC update" ascii wide nocase
        $kyc2 = "complete your KYC" ascii wide nocase
        $kyc3 = "kyc_pending" ascii wide nocase
        $steal1 = "account_blocked" ascii wide nocase
        $steal2 = "net banking" ascii wide nocase
        $steal3 = "debit card" ascii wide nocase
        $steal4 = "cvv" ascii wide nocase
    condition:
        any of ($rbi*) and (any of ($kyc*) or 2 of ($steal*))
}

rule Fake_Ration_Card_App
{
    meta:
        description = "Detects fake ration card / food subsidy apps targeting BPL households"
        severity = "HIGH"
        tags = "ration_card, pds, india, welfare_fraud"
    strings:
        $rc1 = "ration card" ascii wide nocase
        $rc2 = "public distribution" ascii wide nocase
        $rc3 = "PDS" ascii wide
        $rc4 = "food department" ascii wide nocase
        $rc5 = "aanganwadi" ascii wide nocase
        $steal1 = "aadhaar_number" ascii wide nocase
        $steal2 = "family_id" ascii wide nocase
        $steal3 = "beneficiary_id" ascii wide nocase
        $upload1 = "uploadAadhaar" ascii wide nocase
        $upload2 = "submitApplication" ascii wide nocase
    condition:
        any of ($rc*) and (2 of ($steal*) or any of ($upload*))
}

rule Fake_PM_Scheme_App
{
    meta:
        description = "Detects fake PM Kisan / Jan Dhan / Mudra scheme apps used for subsidy fraud"
        severity = "HIGH"
        tags = "pm_scheme, india, subsidy_fraud, government"
    strings:
        $pm1 = "PM Kisan" ascii wide nocase
        $pm2 = "Jan Dhan" ascii wide nocase
        $pm3 = "Mudra Loan" ascii wide nocase
        $pm4 = "Ujjwala" ascii wide nocase
        $pm5 = "Ayushman Bharat" ascii wide nocase
        $pm6 = "PMAY" ascii wide nocase
        $pm7 = "pradhan mantri" ascii wide nocase
        $steal1 = "beneficiary" ascii wide nocase
        $steal2 = "account_number" ascii wide nocase
        $steal3 = "aadhaar_linked" ascii wide nocase
        $money1 = "disbursement" ascii wide nocase
        $money2 = "installment" ascii wide nocase
    condition:
        any of ($pm*) and 2 of ($steal*) and any of ($money*)
}

rule Indian_Stalkerware
{
    meta:
        description = "Detects stalkerware targeting Indian victims — covert relationship monitoring apps"
        severity = "CRITICAL"
        tags = "stalkerware, india, surveillance, domestic_abuse"
    strings:
        $s1 = "track spouse" ascii wide nocase
        $s2 = "monitor wife" ascii wide nocase
        $s3 = "monitor husband" ascii wide nocase
        $s4 = "catch cheating" ascii wide nocase
        $s5 = "track girlfriend" ascii wide nocase
        $s6 = "parental control" ascii wide nocase
        $s7 = "spy app" ascii wide nocase
        $s8 = "hidden spy" ascii wide nocase
        $perm1 = "ACCESS_FINE_LOCATION" ascii wide
        $perm2 = "READ_SMS" ascii wide
        $perm3 = "RECORD_AUDIO" ascii wide
        $perm4 = "READ_CONTACTS" ascii wide
        $hide1 = "hide icon" ascii wide nocase
        $hide2 = "invisible mode" ascii wide nocase
        $hide3 = "stealth mode" ascii wide nocase
    condition:
        any of ($s*) and 2 of ($perm*) and any of ($hide*)
}

rule Fake_Job_Recruitment
{
    meta:
        description = "Detects fake job / work-from-home recruitment scam apps targeting Indian job seekers"
        severity = "HIGH"
        tags = "job_scam, india, recruitment, fraud"
    strings:
        $job1 = "work from home" ascii wide nocase
        $job2 = "earn money online" ascii wide nocase
        $job3 = "part time job" ascii wide nocase
        $job4 = "data entry job" ascii wide nocase
        $job5 = "naukri" ascii wide nocase
        $job6 = "govt job" ascii wide nocase
        $fraud1 = "registration fee" ascii wide nocase
        $fraud2 = "processing fee" ascii wide nocase
        $fraud3 = "security deposit" ascii wide nocase
        $collect1 = "phonepe" ascii wide nocase
        $collect2 = "paytm" ascii wide nocase
        $collect3 = "google pay" ascii wide nocase
        $collect4 = "upi" ascii wide nocase
    condition:
        any of ($job*) and any of ($fraud*) and any of ($collect*)
}

rule Fake_Crypto_Exchange_India
{
    meta:
        description = "Detects fake Indian crypto exchange apps — WazirX, CoinDCX, ZebPay impersonators"
        severity = "CRITICAL"
        tags = "crypto, exchange, india, fraud"
    strings:
        $exc1 = "WazirX" ascii wide nocase
        $exc2 = "CoinDCX" ascii wide nocase
        $exc3 = "ZebPay" ascii wide nocase
        $exc4 = "Bitbns" ascii wide nocase
        $exc5 = "bitcoin india" ascii wide nocase
        $exc6 = "crypto exchange" ascii wide nocase
        $steal1 = "private_key" ascii wide nocase
        $steal2 = "seed_phrase" ascii wide nocase
        $steal3 = "mnemonic" ascii wide nocase
        $steal4 = "wallet_password" ascii wide nocase
        $steal5 = "exchange_api_key" ascii wide nocase
    condition:
        any of ($exc*) and any of ($steal*)
}
