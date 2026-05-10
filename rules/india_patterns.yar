/*
 * CyberKavach YARA Rules — India-Specific Threat Patterns
 * Focused on UPI fraud, loan scams, Aadhaar/PAN theft,
 * and fake Indian banking apps
 */

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
        any of ($upi*) and any of ($malicious*)
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
        any of ($loan*) and $contact1 and $camera1
}

rule Aadhaar_Harvester
{
    meta:
        description = "Detects apps harvesting Aadhaar ID numbers"
        severity = "CRITICAL"
        tags = "aadhaar, identity_theft, india"
    strings:
        $re1 = /[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}/ ascii wide  // Aadhaar format
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
        any of ($bank*) and ($overlay or any of ($steal*))
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
